import requests
import re
from urllib.parse import urljoin, urlparse, quote
from uuid import uuid4
from html import escape
from concurrent.futures import ThreadPoolExecutor, as_completed


def canary(payload, token):
    """
        Append payload with unique token
    """
    return f"{payload}<!--{token}-->"


def detectXSS(body, token,payload, markedPayload):
    """
        If token appears then it's worked
    """
    if token not in body:
        return False

    # If only payload appears its usually safe
    if escape(markedPayload, quote=True) in body:
        return False

    if f"<!--{token}-->" in body:
        return True

    return False




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

            response = self.session.get(url, headers=self.headers, timeout=2, allow_redirects=False)

            # Refresh token
            if self.isDVWA:
                tokenMatch = re.search(r'name=[\'"]user_token[\'"]\s*value=[\'"]([^\'"]+)[\'"]', response.text)
                if tokenMatch:
                    self.userToken = tokenMatch.group(1)


            if detectXSS(response.text, self.token, payload, markedPayload):
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

    def formXSS(self):
        """
            Takes the forms retrieved by the crawler and fuzzes them
        """
        pass

    def storedXSS(self):
        """
            Submits payload then revisits to see if payload still there
        """
        pass

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