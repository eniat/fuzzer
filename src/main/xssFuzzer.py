import requests
import re
from urllib.parse import urljoin, urlparse, quote
from uuid import uuid4
from html import escape
from concurrent.futures import ThreadPoolExecutor, as_completed

SCRIPT_RE = r"<script[^>]*>.*?<!--\s*({token})\s*-->.*?</script>"
ATTR_RE   = r"\bon\w+\s*=\s*(['\"]).*?({token}).*?\1"
JSURL_RE  = r"(?:href|src)\s*=\s*(['\"])\s*javascript:.*?({token}).*?\1"

_regex_cache = {}

SQL = [
    "you have an error in your sql syntax",
    "mysql_fetch", "mysqli_", "pg_query", "syntax error at or near",
    "unclosed quotation mark after the character string", "ora-"
]

def canary(payload, token):
    """
        Append payload with unique token
    """
    return f"{payload}<!--{token}-->"


def detectXSS(body, token, markedPayload):
    """
        If token appears then it's worked
    """
    lowerBody = body.lower()
    token = token.lower()

    if token not in lowerBody:
        return False

    # If only payload appears its usually safe
    if escape(markedPayload, quote=True).lower() in lowerBody:
        return False

    if token not in _regex_cache:

        if len(_regex_cache) >= 32:
            _regex_cache.clear()

        _regex_cache[token] = (
            re.compile(SCRIPT_RE.format(token=re.escape(token)), re.I | re.S),
            re.compile(ATTR_RE.format(token=re.escape(token)), re.I | re.S),
            re.compile(JSURL_RE.format(token=re.escape(token)), re.I | re.S)
        )

    script_re, attr_re, jsurl_re = _regex_cache[token]

    if script_re.search(body) or attr_re.search(body) or jsurl_re.search(body):
        return True

    if any(err in lowerBody for err in SQL):
        return False

    if any(tag in lowerBody for tag in
           ("<img", "<iframe", "<svg", "<a ", "<input", "<video", "<audio")) and f"<!--{token}-->" in lowerBody:
        return True

    return False

def isFuzzableField(field):
    """
        Check if form field is fuzzable
    """
    if not field:
        return False

    lowered = field.lower()

    skips = [
        "user_token", "security", "login", "upload", "change", "submit",
        "max_file_size", "step", "create_db", "password",
        "btnclear", "btnsign", "default"
    ]

    return not any(skip in lowered for skip in skips)



class XSSFuzzer:

    def __init__(self, baseUrl, useCrawler = False, outputToFile= False, wordlistPath=None,isDVWA= False, isSilent=False):
        self.baseUrl = baseUrl
        self.useCrawler = useCrawler
        self.wordlistPath = wordlistPath
        self.outputToFile = outputToFile
        self.payloads = self.loadWordlist()
        self.isSilent = isSilent
        self.token = f"XSSCanary-{uuid4().hex[:8]}"

        self.isDVWA = isDVWA
        self.session = requests.Session()
        self.userToken = ""

        self.vulnerableParams = []

        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
            "Referer": self.baseUrl,
        }

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

    def sendRequest(self, url, payload=None, markedPayload= None):
        """
            Send a single GET request and check for success
        """
        try:
            # Check if DVWA and add token
            if self.isDVWA and self.userToken:
                separator = '&' if '?' in url else '?'
                url = f"{url}{separator}user_token={self.userToken}"

            response = self.session.get(url, headers=self.headers, timeout=3, allow_redirects=False)

            # Refresh token
            if self.isDVWA:
                tokenMatch = re.search(r'name=[\'"]user_token[\'"]\s*value=[\'"]([^\'"]+)[\'"]', response.text)
                if tokenMatch:
                    self.userToken = tokenMatch.group(1)


            if detectXSS(response.text, self.token, markedPayload):
                result = {
                    "url": url,
                    "payload": payload,
                    "status_code": response.status_code,
                    "snippet": response.text[:200]
                }
                self.vulnerableParams.append(result)
                return {"type": "vulnerable", "data": result}

        except requests.exceptions.Timeout:
            # When fuzzing large endpoints timeouts overwhelm, disable if needed
            pass

        except requests.RequestException as e:
            if not self.isSilent:
                print(f"[!] Request failed for {url}: {e}")

        return None

    def paramXSS(self):
        """
            Fuzz query params for reflected XSS
        """
        parsed = urlparse(self.baseUrl)

        if "FUZZ" not in parsed.query:
            print("[-] No 'FUZZ' keyword found")
            return []

        baseNoQuery = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        originalQuery = parsed.query

        tasks = []
        results = []

        with ThreadPoolExecutor(max_workers=20) as executor:
            for payload in self.payloads:
                # Replace FUZZ with the payload
                markedPayload = canary(payload, self.token)
                encoded = quote(markedPayload, safe="")
                fuzzedQuery = originalQuery.replace("FUZZ", encoded)
                fullUrl = f"{baseNoQuery}?{fuzzedQuery}"

                tasks.append(executor.submit(self.sendRequest, fullUrl,payload=payload, markedPayload=markedPayload))

            for future in as_completed(tasks):
                result = future.result()
                if result and "data" in result:
                    results.append(result["data"])
        return results

    def formXSS(self, forms):
        """
            Takes the forms retrieved by the crawler and fuzzes them
        """
        results = []

        with ThreadPoolExecutor(max_workers=20) as executor:
            for form in forms:
                tasks = []
                ctx = {}

                url = form.get("url")
                method = (form.get("method") or "POST").upper()
                fields = form.get("formFields") or[]

                if not url or not fields:
                    continue

                parsed = urlparse(self.baseUrl)
                if not url.startswith("http"):
                    url = f"{parsed.scheme}://{parsed.netloc}{url}"

                for raw in self.payloads:
                    marked = canary(raw, self.token)

                    if method == "POST":
                        data = {}

                        for field in fields:
                            if isFuzzableField(field):
                                data[field] = marked

                            else:
                                data[field] = "test"

                        if self.isDVWA and self.userToken:
                            data.setdefault("user_token", self.userToken)

                        fut = executor.submit(self.session.post, url, data=data, headers=self.headers, timeout=3, allow_redirects=False )

                        tasks.append(fut)
                        ctx[fut] = (url, raw, marked)

                    else:
                        params = []
                        for field in fields:
                            if isFuzzableField(field):
                                params.append(f"{field}={quote(marked, safe='')}")

                            else:
                                params.append(f"{field}=test")

                        separator = "&" if "?" in url else "?"
                        fullUrl = f"{url}{separator}{'&'.join(params)}"

                        fut = executor.submit( self.session.get, fullUrl, headers=self.headers, timeout=3,allow_redirects=False)

                        tasks.append(fut)
                        ctx[fut] = (fullUrl, raw,marked)

                for fut in as_completed(tasks):
                    try:
                        res = fut.result()

                    except Exception:
                        continue

                    finUrl, raw, marked = ctx[fut]

                    if self.isDVWA:
                        tokenMatch = re.search(r'name=[\'"]user_token[\'"]\s*value=[\'"]([^\'"]+)[\'"]', res.text)

                        if tokenMatch:
                            self.userToken = tokenMatch.group(1)


                    if detectXSS(res.text, self.token, marked):
                        results.append({
                            "url": finUrl,
                            "payload": raw,
                            "status_code": res.status_code,
                            "snippet": res.text[:200]
                        })

        return results


    def storedXSS(self, forms,endpoints=None):
        """
            Submits payload then revisits to see if payload still there
        """
        results = []
        pages = set()

        with ThreadPoolExecutor(max_workers=20) as executor:
            for form in forms:
                tasks = []
                ctx = {}

                url = form.get("url")
                method = (form.get("method") or "POST").upper()
                fields = form.get("formFields") or []

                if not url or not fields:
                    continue

                parsed = urlparse(self.baseUrl)
                if not url.startswith("http"):
                    url = f"{parsed.scheme}://{parsed.netloc}{url}"

                pages.add(url)

                for raw in self.payloads:
                    marked = canary(raw,self.token)

                    if method == "POST":
                        data = {}

                        for field in fields:
                            if isFuzzableField(field):
                                data[field] = marked

                            else:
                                data[field] = "test"

                        if self.isDVWA and self.userToken:
                            data.setdefault("user_token", self.userToken)

                        fut = executor.submit(self.session.post, url, data=data, headers=self.headers, timeout=3,allow_redirects=False)

                        tasks.append(fut)
                        ctx[fut] = (url,raw,marked)

                    else:
                        params = []

                        for field in fields:
                            if isFuzzableField(field):
                                params.append(f"{field}={quote(marked, safe='')}")

                            else:
                                params.append(f"{field}=test")

                        separator = "&" if "?" in url else "?"
                        fullUrl = f"{url}{separator}{'&'.join(params)}"

                        fut = executor.submit(self.session.get, fullUrl, headers=self.headers, timeout=3,allow_redirects=False)

                        tasks.append(fut)
                        ctx[fut] = (fullUrl, raw, marked)

                for fut in as_completed(tasks):
                    try:
                        res = fut.result()

                    except Exception:
                        continue

                    finUrl, raw, marked = ctx[fut]

                    if self.isDVWA:
                        tokenMatch = re.search(r'name=[\'"]user_token[\'"]\s*value=[\'"]([^\'"]+)[\'"]', res.text)

                        if tokenMatch:
                            self.userToken = tokenMatch.group(1)


                    if detectXSS(res.text, self.token, marked):
                        results.append({
                            "url": finUrl,
                            "payload": raw,
                            "status_code": res.status_code,
                            "snippet": res.text[:200]
                        })

                    if res.status_code in (301, 302, 303,307, 308):
                        loc = res.headers.get("Location")
                        if loc:
                            pages.add(loc if loc.startswith("http")else urljoin(finUrl, loc))

        if endpoints:
            parsed = urlparse(self.baseUrl)
            base = f"{parsed.scheme}://{parsed.netloc}"

            for end in endpoints:
                if not end:
                    continue

                pages.add(end if end.startswith("http") else f"{base}{end}")

        markedPayloads = [(raw, canary(raw, self.token)) for raw in self.payloads]

        with ThreadPoolExecutor(max_workers=20) as executor:

            futToPage = {
                executor.submit(self.session.get,page
                if (not (self.isDVWA and self.userToken)) else
                    f"{page}{'&' if '?' in page else '?'}user_token={self.userToken}",
                    headers=self.headers,
                    timeout=3,
                    allow_redirects=True
                ): page
                for page in pages
            }

            for fut in as_completed(futToPage):

                finUrl = futToPage[fut]
                try:
                    res = fut.result()

                except Exception:
                    continue

                # Refresh DVWA token if needed
                if self.isDVWA:
                    tokenMatch = re.search(
                        r'name=[\'"]user_token[\'"]\s*value=[\'"]([^\'"]+)[\'"]',
                        res.text
                    )
                    if tokenMatch:
                        self.userToken = tokenMatch.group(1)

                body = res.text
                lowerBody = body.lower()

                if self.token.lower() not in lowerBody:
                    continue

                for raw, marked in markedPayloads:
                    if detectXSS(body, self.token, marked):
                        results.append({
                            "url": finUrl,
                            "payload": raw,
                            "status_code": res.status_code,
                            "snippet": body[:200]
                        })

                        break

        return results


    def domXSS(self):
        """
            Submits payload then loads and checks JS for payload
        """
        pass

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