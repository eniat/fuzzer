import re
import requests
from urllib.parse import urlparse


SQL = [
    "you have an error in your sql syntax",
    "mysql_fetch", "mysqli_", "pg_query", "syntax error at or near",
    "unclosed quotation mark after the character string", "ora-"
]

def detectSQLi(body):
    """
        If payload works then it flags true
    """
    pass

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

            # SQLi detection
            if detectSQLi(response.text):
                result = {
                    "url": url,
                    "payload": payload,
                    "status_code": response.status_code,
                    "snippet": (response.text or "")[:200]
                }

                self.vulnerableForms.append(result)
                return {"type": "vulnerable", "data": result}

        except requests.exceptions.Timeout:
            # When fuzzing large endpoints timeouts overwhelm, disable if needed
            pass

        except requests.RequestException as e:
            if not self.isSilent:
                print(f"[!] Request failed for {url}: {e}")

        return None

    def SQLiFuzz(self, forms):
        """
            Takes the forms retrieved by the crawler and fuzzes them for SQLi vulnerabilities
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