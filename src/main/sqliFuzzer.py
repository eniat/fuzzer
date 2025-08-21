import re
import requests
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher

from xssFuzzer import isFuzzableField, detectXSS

SQL = [
    "you have an error in your sql syntax",
    "mysql_fetch", "mysqli_", "pg_query", "syntax error at or near",
    "unclosed quotation mark after the character string", "ora-",
    "unknown column", "no such column", "unrecognized token",
    "near \"select\"", "warning: mysql", "odbc sql server driver",
    "sqlstate", "quoted string not properly terminated"
]

def detectSQLError(body):
    """
        Detects SQL errors which highlights potential vulnerabilities
    """
    lower = (body or "").lower()

    for err in SQL:
        if err in lower:
            return True, err

    return False, None

def detectSQLi(baseText, baseStatus, resBody ,resStatus, simThreshold= 0.90, deltaThreshold= 50):
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

    def __init__(self, baseUrl, useCrawler=False, outputToFile= False, wordlistPath=None,isDVWA=False, isSilent= False):
        self.baseUrl = baseUrl
        self.useCrawler = useCrawler
        self.wordlistPath = wordlistPath
        self.outputToFile = outputToFile
        self.isSilent = isSilent

        # For testing
        self.isDVWA = isDVWA
        self.session = requests.Session()
        self.userToken = ""

        self.payloads = self.loadWordlist() if self.wordlistPath is not None else []

        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
            "Referer": self.baseUrl,
        }

        self.vulnerableForms = []

        if self.isDVWA:
            self.login()

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

                if self.isDVWA and self.userToken:
                    baseData.setdefault("user_token", self.userToken)

                res = self.session.post(endpoint, data= baseData,headers=self.headers, timeout= 2, allow_redirects=False)

            else:
                params = [f"{f}=test" for f in fields]
                sep = "&" if "?" in endpoint else "?"
                baseUrl = f"{endpoint}{sep}{'&'.join(params)}"

                if self.isDVWA and self.userToken:
                    baseUrl = f"{baseUrl}{'&' if '?' in baseUrl else '?'}user_token={self.userToken}"

                res = self.session.get(baseUrl,headers=self.headers, timeout= 2, allow_redirects=False)

            baseText, baseStatus = res.text or "", res.status_code

            if self.isDVWA:
                m = re.search(r'name=[\'"]user_token[\'"]\s*value=[\'"]([^\'"]+)[\'"]', baseText)

                if m:
                    self.userToken = m.group(1)

            return baseText, baseStatus

        except Exception:
            return "",0

    def SQLiFuzz(self, forms):
        """
            Takes the forms retrieved by the crawler and fuzzes them for SQLi vulnerabilities
        """
        results = []

        with ThreadPoolExecutor(max_workers=20) as executor:
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


                        if self.isDVWA and self.userToken:
                            data.setdefault("user_token", self.userToken)

                        fut = executor.submit(self.session.post, url, data=data, headers=self.headers, timeout=3, allow_redirects=False)

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

                        if self.isDVWA and self.userToken:
                            fullUrl = f"{fullUrl}{'&' if '?' in fullUrl else '?'}user_token={self.userToken}"

                        fut = executor.submit( self.session.get, fullUrl, headers=self.headers, timeout=3,allow_redirects=False)

                        tasks.append(fut)
                        ctx[fut] = (fullUrl, raw)

                # collect responses as they finish
                for fut in as_completed(tasks):
                    try:
                        res = fut.result()

                    except Exception:
                        continue

                    finUrl, raw = ctx[fut]

                    # DVWA token refresh
                    if self.isDVWA:
                        tokenMatch = re.search(
                            r'name=[\'"]user_token[\'"]\s*value=[\'"]([^\'"]+)[\'"]',
                            res.text or ""
                        )
                        if tokenMatch:
                            self.userToken = tokenMatch.group(1)

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

    def login(self):
        """
            Log in to DVWA using default credentials and set security to low
        """

        parsed = urlparse(self.baseUrl)
        base = f"{parsed.scheme}://{parsed.netloc}"

        loginUrl = f"{base}/login.php"
        securityUrl = f"{base}/security.php"

        try:
            loginPage = self.session.get(loginUrl, headers=self.headers)
            # print("[DEBUG] Login page response\n:", loginPage.text)

            tokenMatch = re.search(r'name=[\'"]user_token[\'"]\s*value=[\'"]([^\'"]+)[\'"]', loginPage.text)

            token = tokenMatch.group(1) if tokenMatch else ''
            # print(f"[DEBUG] CSRF token from login page:{token}")

            if not token:
                print("[!] Could not extract CSRF token from login page!")

                return False

            loginData = {
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": token
            }

            res = self.session.post(loginUrl, data=loginData, headers=self.headers)

            if "Login failed" in res.text:
                print("[!] Login failed. Check credentials.")
                return False

            securityPage = self.session.get(securityUrl, headers=self.headers)
            tokenMatch = re.search(r'name=[\'"]user_token[\'"]\s*value=[\'"]([^\'"]+)[\'"]', securityPage.text)
            token = tokenMatch.group(1) if tokenMatch else ''

            securityData = {
                "security": "low",
                "seclev_submit": "Submit",
                "user_token": token
            }

            self.session.post(securityUrl, data=securityData, headers=self.headers)
            # print("[+] Logged in to DVWA and set security level to low")

            return True

        except requests.RequestException as e:
            print(f"[!] Login request failed: {e}")
            return False