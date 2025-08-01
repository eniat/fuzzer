from urllib.parse import urljoin, urlparse, parse_qs, urldefrag
import requests
import argparse
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import PurePosixPath

from crawler import Crawler

class PathFuzzer:

    def __init__(self, baseUrl, useCrawler = False, wordlistPath= None, outputToFile = False, maxDepth= 3, isDVWA =False):
        self.baseUrl = baseUrl
        self.useCrawler = useCrawler
        self.wordlistPath = wordlistPath
        self.outputToFile = outputToFile
        self.maxDepth =  maxDepth
        self.payloads = self.loadWordlist()

        # For testing
        self.isDVWA = isDVWA
        self.session = requests.Session()
        self.userToken = ""

        # results storage
        self.visitedPaths = set()
        self.vulnerablePaths = []

        self.indicators = [
            "root:x:0:0", "daemon:x", "bin:x", "/bin/bash",
            "[boot loader]", "[extensions]", "boot.ini",
            "illegal file type", "enoent", "eacces", "failed to open stream",
            "stack trace", " at /", "open '/etc/passwd'", "cannot open file",
            "no such file or directory", "permission denied", "failed opening required"
        ]
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
            "Referer": self.baseUrl,
        }

        if isDVWA:
            self.login()


    def loadWordlist(self):
        """
            Load payload from wordlist
        """
        try:
            with open(self.wordlistPath, 'r', encoding='utf-8', errors='replace') as f:
                # Strips the lines
                return [line.strip() for line in f if line.strip()]
        except Exception as e :
            # On error raise exception
            raise RuntimeError( f"Failed to load wordlist from {self.wordlistPath}: {e}")

    def getInitalPaths(self):
        """
            Get paths from the crawler or use base
        """
        # Runs crawler to get paths
        if self.useCrawler:
            crawler = Crawler(outputToFile= False)
            endpoints, _ = crawler.crawl(self.baseUrl)
            allPaths = set()
            for ep in endpoints:
                url = ep["url"]
                path = PurePosixPath(url)

                for p in path.parents:
                    if str(p) != ".":
                        allPaths.add(str(p))

                allPaths.add(str(path))

            return list(allPaths), endpoints
        # If crawler isn't wanted uses baseUrl as starting point
        else:
            parsed = urlparse(self.baseUrl)
            return [parsed.path or "/"], [{"url" : parsed.path or "/", "params": list(parse_qs(parsed.query).keys())} ]

    def isPathTraversalSuccess(self, response, url):
        """
            Detect success based on response
        """
        if response.status_code != 200:
            return False

        content = response.text.lower()

        # print(f"[DEBUG] Response preview: {content[:300]}")
        for indicator in self.indicators:
            if indicator in content:
                # print(f"[DEBUG] Matched indicator '{indicator}' in response from {url}")
                return True

        return any(indicator in content for indicator in self.indicators)

    def  fuzzPath(self, path, currDepth= 0):
        """
            Fuzz the URL path using the payload
        """
        if currDepth > self.maxDepth:
            return

        tasks = []
        results = []

        parsed = urlparse(self.baseUrl)
        base = f"{parsed.scheme}://{parsed.netloc}"

        with ThreadPoolExecutor(max_workers= 20) as executor:

            for payload in self.payloads:
                # Check for /
                basePath = path if path.endswith('/') else path + '/'
                fullPath = basePath + payload

                targetUrl = f"{base}/{fullPath.lstrip('/')}"

                if targetUrl in self.visitedPaths:
                    continue

                self.visitedPaths.add(targetUrl)
                tasks.append(executor.submit(self.sendRequest, targetUrl, currDepth))

            for future in as_completed(tasks):
                result  = future.result()
                if result :
                    foundPath, newDepth = result
                    fullUrl = f"{base}{foundPath}"
                    print(f"[+] Vulnerability found at: {fullUrl }")
                    results.append((foundPath, newDepth))

        for (nextPath, nextDepth) in results:
            self.fuzzPath(nextPath, currDepth=nextDepth)

    def sendRequest(self, url, depth):
        """
            Send a single GET request and check for success
        """
        try:
            response = self.session.get(url, headers=self.headers, timeout=5)
            if self.isPathTraversalSuccess(response, url):

                self.vulnerablePaths.append(url)
                return urlparse(url).path, depth + 1

        except requests.RequestException as e:
            print(f"[!] Request failed for {url}: {e}")

        return None

    def fuzzParams(self, endpoint):
        """
            Fuzz query params
        """
        parsed = urlparse(self.baseUrl)

        if "FUZZ" not in parsed.query:
            print("[-] No 'FUZZ' keyword found")
            return []

        baseNoQuery = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        originalQuery = parsed.query

        vulnerable = []

        for payload in self.payloads:
            # Replace FUZZ with the payload
            fuzzedQuery = originalQuery.replace("FUZZ", payload)

            if self.isDVWA and self.userToken:
                fuzzedQuery += f"&user_token={self.userToken}"
            fullUrl = f"{baseNoQuery}?{fuzzedQuery}"

            try:
                response = self.session.get(fullUrl, headers=self.headers, timeout=5, allow_redirects=False)

                # print("[DEBUG] Final URL:", response.url)
                # print(f"[DEBUG] Trying: {fullUrl}")
                # print(f"[DEBUG] Status: {response.status_code}, Length: {len(response.text)}")

                if self.isPathTraversalSuccess(response, fullUrl):
                    # print(f"[+] Vulnerability found at: {fullUrl}")
                    vulnerable.append(fullUrl)
                    self.vulnerablePaths.append(fullUrl)

            except requests.RequestException as e:
                print(f"[!] Failed to fuzz with {payload}: {e}")

        return vulnerable

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

            res = self.session.post(loginUrl, data=loginData,headers=self.headers)

            if "Login failed" in res.text:
                print("[!] Login failed. Check credentials.")
                return False

            securityPage = self.session.get(securityUrl, headers= self.headers)
            tokenMatch = re.search(r'name=[\'"]user_token[\'"]\s*value=[\'"]([^\'"]+)[\'"]', securityPage.text)
            token = tokenMatch.group(1) if tokenMatch else ''

            securityData = {
                "security": "low",
                "seclev_submit": "Submit",
                "user_token": token
            }

            self.session.post(securityUrl, data=securityData, headers= self.headers)
            print("[+] Logged in to DVWA and set security level to low")

            return True

        except requests.RequestException as e:
            print(f"[!] Login request failed: {e}")
            return False

    def run(self,fuzzParams= True, fuzzPaths=True):
        """
        Main entry to run fuzzing
        """

        paths, endpoints = self.getInitalPaths()

        # If any endpoints with query params exist FUZZ
        if fuzzParams:
            for ep in endpoints:
                if ep["params"]:
                    self.fuzzParams(ep)

        # Fuzz discovered or base paths
        if fuzzPaths:
            for path in paths:
                # For debugging
                # print(f"Fuzzing: {path}")
                self.fuzzPath(path)

        if self.outputToFile:
            with open("pathFuzzerOutput.txt", "w") as f:
                for vuln in self.vulnerablePaths:
                    f.write(f"{vuln}\n")
        else:
            if self.vulnerablePaths:
                print("\n[+] Vulnerabilities found at:")
                for path in self.vulnerablePaths:
                    print(f"  - {path}")
            else:
                print("[-] No vulnerabilities found.")

if __name__ == "__main__":

    parser = argparse.ArgumentParser( description="Path Traversal Fuzzer")
    parser.add_argument("--url", required=True, help="Base URL to fuzz")
    parser.add_argument("--wordlist", required=True, help="Path to traversal payload wordlist")
    parser.add_argument("--use-crawler", action="store_true", help="Use crawler to discover paths")
    parser.add_argument("--output-to-file", action="store_true", help="Write results to a file")
    parser.add_argument("--fuzz-params", action="store_true", help="Enable parameter fuzzing")
    parser.add_argument("--fuzz-paths", action="store_true", help="Enable path traversal fuzzing")

    # For testing
    parser.add_argument("--dvwa", action="store_true", help="Auto-login to DVWA and set security to low")


    args = parser.parse_args()

    fuzzer = PathFuzzer(
        baseUrl=args.url,
        useCrawler=args.use_crawler,
        wordlistPath=args.wordlist,
        outputToFile=args.output_to_file,
        isDVWA=args.dvwa
    )

    if args.fuzz_params and not args.fuzz_paths:
        fuzzer.run(fuzzParams=True, fuzzPaths=False)

    elif args.fuzz_paths and not args.fuzz_params:
        fuzzer.run(fuzzParams=False, fuzzPaths=True)

    else:
        fuzzer.run(fuzzParams=True, fuzzPaths=True)


