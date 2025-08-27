import requests
import threading
import re
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

from requests.adapters import HTTPAdapter

from uni_fuzzer.auth.auth import login

from uni_fuzzer.core.utility import get_cfg, isFuzzableField
cfg = get_cfg()

SQL = cfg["sqli"]["error_signatures"]
MAX_SAMPLES_PER_GROUP = cfg["sqli"]["max_samples_per_group"]
TIMING_THRESHOLD_MS = cfg["sqli"]["timing_threshold_ms"]
BLIND_MARKERS = cfg["sqli"]["blind_markers"]
BLIND_FACTOR  = cfg["sqli"]["blind_timing_factor"]
BLIND_TIME = cfg["sqli"]["blind_time"]

def detectSQLError(body):
    """
        Detects SQL errors which highlights potential vulnerabilities
    """
    lower = (body or "").lower()

    for err in SQL:
        if err in lower:
            return True, err

    return False, None

def isBlindPayload (payload):
    """
        Checks if payload is a blind payload
    """
    low = (payload or "").lower()
    return any(mark in low for mark in BLIND_MARKERS) and bool(re.search(r"\d", low))

def detectSQLiBlind(baseMs, testMs, thresholdMs= TIMING_THRESHOLD_MS, factor=BLIND_FACTOR):
    """
        Detects SQLi blind by checking timing difference
    """
    delta = testMs - baseMs
    if delta <= 0:
        return False
    baseline = max(baseMs, 200.0)

    return (delta >= thresholdMs) or (testMs >= baseline * factor)

def expandTimeToken(payload, seconds=BLIND_TIME):
    """
        Replaces __TIME__ in payload strings with the configured number of seconds
    """
    return (payload or "").replace("__TIME__", str(seconds))

def detectSQLiContent(baseHtml, html):
    """
        Checks if rows or records appear in html
    """
    b = (baseHtml or "").lower()
    h = (html or "").lower()
    rowsB = b.count("<tr")
    rowsH = h.count("<tr")

    lisB  = baseHtml.count("<li")
    lisH  = html.count("<li")

    return (rowsH > rowsB) or (lisH > lisB)

class SQLiFuzzer:

    def __init__(self, baseUrl, useCrawler=False, outputToFile= False, wordlistPath=None, isSilent= False, session=None, loginUsername=None, loginPassword=None, loginPath=None, auth=False):
        self.baseUrl = baseUrl
        self.useCrawler = useCrawler
        self.wordlistPath = wordlistPath
        self.outputToFile = outputToFile
        self.isSilent = isSilent

        # Authentication
        self.session = session or requests.Session()
        if session is None:
            mw = int(cfg["concurrency"]["max_workers"])
            adapter = HTTPAdapter(pool_connections=mw, pool_maxsize=mw, max_retries=0)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
            self.session.trust_env = False
        self.loginUsername = loginUsername
        self.loginPassword = loginPassword
        self.loginPath = loginPath
        self.auth = auth

        self.payloads = self.loadWordlist() if self.wordlistPath is not None else []

        self.headers = {"User-Agent": cfg["http"]["user_agent"],}
        if cfg["http"]["add_referer"]:
            self.headers["Referer"] = self.baseUrl

        self.vulnerableForms = {}
        self.lock = threading.Lock()

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
            elapses = []

            if method == "POST":
                baseData = {f: "test" for f in fields}

                res = self.session.post(
                    endpoint,
                    data=baseData,
                    headers=self.headers,
                    timeout=cfg["sqli"]["timeout_blind"],
                    allow_redirects=cfg["http"]["redirects"]["baseline_post"]
                )

                baseText, baseStatus = res.text or "", res.status_code

                data = {f: "1" for f in fields}

                for _ in range(3):
                    r = self.session.post(
                        endpoint,
                        data=data,
                        headers=self.headers,
                        timeout=cfg["sqli"]["timeout_blind"],
                        allow_redirects=cfg["http"]["redirects"]["baseline_post"]
                    )
                    elapses.append(r.elapsed.total_seconds() * 1000.0)

            else:
                baseQuery = "&".join(f"{f}=test" for f in fields)
                sep = "&" if "?" in endpoint else "?"
                baseUrl = f"{endpoint}{sep}{baseQuery}"

                res = self.session.get(
                    baseUrl,
                    headers=self.headers,
                    timeout=cfg["sqli"]["timeout_blind"],
                    allow_redirects=cfg["http"]["redirects"]["baseline_get"]
                )

                baseText, baseStatus = res.text or "", res.status_code

                query = "&".join(f"{f}=1" for f in fields)
                baseUrl = f"{endpoint}{sep}{query}"

                for _ in range(3):
                    r = self.session.get(
                        baseUrl,
                        headers=self.headers,
                        timeout=cfg["sqli"]["timeout_blind"],
                        allow_redirects=cfg["http"]["redirects"]["baseline_get"]
                    )
                    elapses.append(r.elapsed.total_seconds() * 1000.0)

            elapses.sort()
            baselineMs = elapses[1] if len(elapses) >= 3 else (elapses[0] if elapses else 0.0)
            return baseText, baseStatus, baselineMs

        except Exception:
            return "",0,0.0

    def SQLiFuzz(self, forms):
        """
            Takes the forms retrieved by the crawler and fuzzes them for SQLi vulnerabilities
        """

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
                baseText, baseStatus, baselineMs = self.getBaseline(url, method, fields)

                for raw in self.payloads:
                    payload = expandTimeToken(raw)
                    if method == "POST":
                        # POST form fuzzing
                        data = {}

                        for field in fields:
                            # Inject payload into fuzzable fields
                            if isFuzzableField(field):
                                data[field] = payload

                            else:
                                data[field] = "test"

                        fut = executor.submit(self.session.post, url, data=data, headers=self.headers, timeout=cfg["sqli"]["timeout_blind"], allow_redirects=cfg["http"]["redirects"]["fuzz_post"])

                        tasks.append(fut)
                        ctx[fut] = (url, payload)

                    else:
                        # GET form fuzzing
                        params = []
                        for field in fields:
                            if isFuzzableField(field):
                                params.append(f"{field}={quote(payload, safe='')}")

                            else:
                                params.append(f"{field}=test")

                        # Contruct GET requests
                        separator = "&" if "?" in url else "?"
                        fullUrl = f"{url}{separator}{'&'.join(params)}"

                        fut = executor.submit( self.session.get, fullUrl, headers=self.headers, timeout=cfg["sqli"]["timeout_blind"],allow_redirects=cfg["http"]["redirects"]["fuzz_get"])

                        tasks.append(fut)
                        ctx[fut] = (fullUrl, payload)

                # collect responses as they finish
                for fut in as_completed(tasks):
                    try:
                        res = fut.result()

                    except Exception:
                        continue

                    finUrl, payload = ctx[fut]


                    body = res.text or ""
                    status = res.status_code

                    # Check for SQL Error
                    isErr, indicator = detectSQLError(body)

                    if isErr:
                        pageKey = finUrl.split("?", 1)[0].split("#", 1)[0]
                        resultsKey = (pageKey, indicator or "N/A", "potential")

                        with self.lock:
                            if resultsKey not in self.vulnerableForms:
                                self.vulnerableForms[resultsKey] = {
                                    "url": pageKey,
                                    "payload": payload,
                                    "payload_samples": [raw] if raw else [],
                                    "status_code": status,
                                    "indicator": indicator or "N/A",
                                    "snippet": (body or "")[:200],
                                    "count": 1,
                                    "type": "potential",
                                }

                            else:
                                entry = self.vulnerableForms[resultsKey]
                                entry["count"] += 1
                                if raw and len(entry["payload_samples"]) < MAX_SAMPLES_PER_GROUP:
                                    entry["payload_samples"].append(raw)
                        continue

                    # Check for blind SQLi
                    if isBlindPayload(payload):
                        testMs = res.elapsed.total_seconds() * 1000.0

                        if detectSQLiBlind(baselineMs, testMs):
                            try:
                                if res.request.method.upper() == "POST":
                                    confirm = self.session.post(
                                        res.request.url,
                                        data=res.request.body if res.request.body else {},
                                        headers=self.headers,
                                        timeout=cfg["sqli"]["timeout_blind"],
                                        allow_redirects=cfg["http"]["redirects"]["fuzz_post"],
                                    )

                                else:
                                    confirm = self.session.get(
                                        res.request.url,
                                        headers=self.headers,
                                        timeout=cfg["sqli"]["timeout_blind"],
                                        allow_redirects=cfg["http"]["redirects"]["fuzz_get"],
                                    )

                                confirmMs = confirm.elapsed.total_seconds() * 1000.0

                                if not detectSQLiBlind(baselineMs, confirmMs):
                                    continue

                            except Exception:
                                continue

                            pageKey = finUrl.split("?", 1)[0].split("#", 1)[0]
                            ind = "blind_sql"
                            resultsKey = (pageKey, ind, "vulnerable")

                            with self.lock:
                                if resultsKey not in self.vulnerableForms:
                                    self.vulnerableForms[resultsKey] = {
                                        "url": pageKey,
                                        "payload":raw,
                                        "payload_samples": [raw] if raw else [],
                                        "status_code": status,
                                        "indicator": ind,
                                        "snippet": (body or "")[:200],
                                        "count": 1,
                                        "type": "vulnerable",
                                    }

                                else:
                                    entry = self.vulnerableForms[resultsKey]
                                    entry["count"] += 1
                                    if raw and len(entry["payload_samples"]) < MAX_SAMPLES_PER_GROUP:
                                        entry["payload_samples"].append(raw)

                        continue

                    # Check for valid SQLi ran code
                    if baseStatus:
                        if status != baseStatus or detectSQLiContent(baseText, body):

                            pageKey = finUrl.split("?", 1)[0].split("#", 1)[0]
                            resultsKey = (pageKey, "detected_sql_content", "vulnerable")

                            with self.lock:
                                if resultsKey not in self.vulnerableForms:
                                    self.vulnerableForms[resultsKey] = {
                                        "url": pageKey,
                                        "payload": raw,
                                        "payload_samples": [raw] if raw else [],
                                        "status_code": status,
                                        "indicator": "detected_sql_content",
                                        "snippet": (body or "")[:200],
                                        "count": 1,
                                        "type": "vulnerable",
                                    }

                                else:
                                    entry = self.vulnerableForms[resultsKey]
                                    entry["count"] += 1
                                    if raw and len(entry["payload_samples"]) < MAX_SAMPLES_PER_GROUP:
                                        entry["payload_samples"].append(raw)
        return list(self.vulnerableForms.values())
