import re
import requests
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher

from uni_fuzzer.auth.auth import login

from uni_fuzzer.core.utility import get_cfg, isFuzzableField
cfg = get_cfg()

SQL = cfg["sqli"]["error_signatures"]

def detectSQLError(body):
    """
        Detects SQL errors which highlights potential vulnerabilities
    """
    lower = (body or "").lower()

    for err in SQL:
        if err in lower:
            return True, err

    return False, None

def detectSQLi(baseText, baseStatus, resBody ,resStatus, simThreshold=cfg["sqli"]["similarity_threshold"], deltaThreshold=cfg["sqli"]["size_delta_threshold"]):
    """
        If payload works then it flags true and returns indicator
    """

    try:
        if baseStatus != resStatus:
            return True, f"status_change({baseStatus}->{resStatus})"

        sim = SequenceMatcher(None, baseText or "", resBody or "").quick_ratio()

        if sim < simThreshold:
            return True, f"diff(sim={sim:.2f})"

        if abs(len(resBody or "") - len(baseText or "")) > deltaThreshold:
            return True, f"size_delta(>{deltaThreshold})"

    except Exception:
        pass

    return False, None

class SQLiFuzzer:

    def __init__(self, baseUrl, useCrawler=False, outputToFile= False, wordlistPath=None, isSilent= False, session=None, loginUsername=None, loginPassword=None, loginPath=None, auth=False):
        self.baseUrl = baseUrl
        self.useCrawler = useCrawler
        self.wordlistPath = wordlistPath
        self.outputToFile = outputToFile
        self.isSilent = isSilent

        # Authentication
        self.session = session or requests.Session()
        self.loginUsername = loginUsername
        self.loginPassword = loginPassword
        self.loginPath = loginPath
        self.auth = auth

        self.payloads = self.loadWordlist() if self.wordlistPath is not None else []

        self.headers = {"User-Agent": cfg["http"]["user_agent"],}
        if cfg["http"]["add_referer"]:
            self.headers["Referer"] = self.baseUrl

        self.vulnerableForms = []

        if self.auth and self.loginUsername and self.loginPassword:
            ok = login(self.session, self.baseUrl, self.loginUsername, self.loginPassword, self.loginPath)
            if not ok:
                print("[-] HTTP login in SQLi Fuzzer failed")

    def loadWordlist(self):
        """
            Load payload from wordlist
        """
        # Check if list is passed
        if isinstance(self.wordlistPath, list):
            return self.wordlistPath

        try:
            with open(self.wordlistPath, 'r', encoding='utf-8', errors='replace') as f:
                # Strips the lines
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            # On error raise exception
            raise RuntimeError(f"[-] Failed to load wordlist from {self.wordlistPath}: {e}")

    def getBaseline(self, endpoint, method, fields):
        """
            Get baseline to compare if SQLi worked
        """
        try:
            if method == "POST":
                baseData = {f: "test" for f in fields}

                res = self.session.post(endpoint, data= baseData,headers=self.headers, timeout=cfg["http"]["timeout_post_seconds"], allow_redirects=cfg["http"]["redirects"]["baseline_post"])

            else:
                params = [f"{f}=test" for f in fields]
                sep = "&" if "?" in endpoint else "?"
                baseUrl = f"{endpoint}{sep}{'&'.join(params)}"

                res = self.session.get(baseUrl,headers=self.headers, timeout=cfg["http"]["timeout_get_seconds"], allow_redirects=cfg["http"]["redirects"]["baseline_get"])

            baseText, baseStatus = res.text or "", res.status_code

            return baseText, baseStatus

        except Exception:
            return "",0

    def SQLiFuzz(self, forms):
        """
            Takes the forms retrieved by the crawler and fuzzes them for SQLi vulnerabilities
        """
        results = []

        with ThreadPoolExecutor(max_workers=cfg["concurrency"]["max_workers"]) as executor:
            for form in forms:
                tasks = []
                # To track future information for saving
                ctx = {}

                url = form.get("url")
                method = (form.get("method") or "POST").upper()
                fields = form.get("formFields") or []

                # Skip invalid form objects
                if not url or not fields:
                    continue

                # Normalize Urls
                parsed = urlparse(self.baseUrl)

                if not url.startswith("http"):
                    url = f"{parsed.scheme}://{parsed.netloc}{url}"

                # Get a baseline for later comparisons
                baseText, baseStatus = self.getBaseline(url, method, fields)

                for raw in self.payloads:
                    if method == "POST":
                        # POST form fuzzing
                        data = {}

                        for field in fields:
                            # Inject payload into fuzzable fields
                            if isFuzzableField(field):
                                data[field] = raw

                            else:
                                data[field] = "test"

                        fut = executor.submit(self.session.post, url, data=data, headers=self.headers, timeout=cfg["http"]["timeout_post_seconds"], allow_redirects=cfg["http"]["redirects"]["fuzz_post"])

                        tasks.append(fut)
                        ctx[fut] = (url, raw)

                    else:
                        # GET form fuzzing
                        params = []
                        for field in fields:
                            if isFuzzableField(field):
                                params.append(f"{field}={quote(raw, safe='')}")

                            else:
                                params.append(f"{field}=test")

                        # Contruct GET requests
                        separator = "&" if "?" in url else "?"
                        fullUrl = f"{url}{separator}{'&'.join(params)}"

                        fut = executor.submit( self.session.get, fullUrl, headers=self.headers, timeout=cfg["http"]["timeout_get_seconds"],allow_redirects=cfg["http"]["redirects"]["fuzz_get"])

                        tasks.append(fut)
                        ctx[fut] = (fullUrl, raw)

                # collect responses as they finish
                for fut in as_completed(tasks):
                    try:
                        res = fut.result()

                    except Exception:
                        continue

                    finUrl, raw = ctx[fut]


                    body = res.text or ""
                    status = res.status_code

                    # Check for SQL Error
                    isErr, indicator = detectSQLError(body)
                    if isErr:
                        hit = {
                            "url": finUrl,
                            "payload":raw,
                            "status_code": status,
                            "indicator": indicator,
                            "response_snippet": body[:200],
                            "type": "potential"
                        }

                        self.vulnerableForms.append(hit)
                        results.append(hit)
                        continue

                    # Check for valid SQLi ran code
                    if baseText or baseStatus is not None:
                        isPos, posInd = detectSQLi(baseText, baseStatus, body, status)
                        if isPos:
                            hit = {
                                "url": finUrl,
                                "payload": raw,
                                "status_code": status,
                                "indicator": posInd,
                                "response_snippet": body[:200],
                                "type": "vulnerable"
                            }
                            self.vulnerableForms.append(hit)
                            results.append(hit)
        return results
