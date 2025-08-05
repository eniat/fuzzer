from urllib.parse import urljoin, urlparse, parse_qs, urldefrag
import requests
import argparse
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import PurePosixPath

from crawler import Crawler

class PathFuzzer:

    def __init__(self, baseUrl, useCrawler = False, wordlistPath= None, outputToFile = False, maxDepth= 3, isDVWA =False, isSilent= False):
        self.baseUrl = baseUrl
        self.useCrawler = useCrawler
        self.wordlistPath = wordlistPath
        self.outputToFile = outputToFile
        self.maxDepth =  maxDepth
        self.payloads = self.loadWordlist()
        self.isSilent = isSilent

        # For testing
        self.isDVWA = isDVWA
        self.session = requests.Session()
        self.userToken = ""

        # results storage
        self.visitedPaths = set()
        self.vulnerablePaths = []

        self.indicators = [
            "root:x:0:0", "daemon:x", "bin:x", "/bin/bash",
            "[boot loader]", "[extensions]", "multi(0)disk(0)rdisk(0)",
            "illegal file type", "enoent", "eacces", "failed to open stream",
            "stack trace", " at /", "open '/etc/passwd'", "cannot open file",
            "permission denied", "failed opening required", "linux version",
            "include(", "require(", "c:\\windows\\system32","\\r\\n", "<drive>",
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
        content = response.text.lower()

        # Check for indicators in response
        for indicator in self.indicators:
            if indicator in content:
                #print(f"[DEBUG] Matched indicator '{indicator}' in response from {url}")
                return indicator

        return None

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
                # print(targetUrl)

                if targetUrl in self.visitedPaths:
                    continue

                self.visitedPaths.add(targetUrl)
                tasks.append(executor.submit(self.sendRequest, targetUrl, currDepth, isParamFuzzing=False,payload=payload))

            for future in as_completed(tasks):
                result  = future.result()
                if result :
                    foundPath = result["url"]
                    newDepth = result["depth"]
                    fullUrl = f"{base}{foundPath}"
                    print(f"[+] Vulnerability found at: {fullUrl }")
                    results.append((foundPath, newDepth))

        for (nextPath, nextDepth) in results:
            self.fuzzPath(nextPath, currDepth=nextDepth)

    def sendRequest(self, url, depth, isParamFuzzing= False,payload= None):
        """
            Send a single GET request and check for success
        """
        try:
            # Check if DVWA and add token
            if self.isDVWA and self.userToken:
                separator = '&' if '?' in url else '?'
                url = f"{url}{separator}user_token={self.userToken}"

            response = self.session.get(url, headers=self.headers, timeout=5, allow_redirects= False)

            # Refresh token
            if self.isDVWA:
                tokenMatch = re.search(r'name=[\'"]user_token[\'"]\s*value=[\'"]([^\'"]+)[\'"]',response.text )
                if tokenMatch:
                    self.userToken = tokenMatch.group(1)

            indicator = self.isPathTraversalSuccess(response,url)

            if indicator:

                result = {
                    "url": url if isParamFuzzing else urlparse(url).path,
                    "payload": payload,
                    "type": "param" if isParamFuzzing else "path",
                    "depth": depth + 1 if not isParamFuzzing else 0,
                    "status_code": response.status_code,
                    "indicator": indicator,
                    "response_snippet": response.text[:200]
                }

                if not isParamFuzzing:
                    self.vulnerablePaths.append(result)

                return result

        except requests.exceptions.Timeout:
            # When fuzzing large endpoints timeouts overwhelm, disable if needed
            pass

        except requests.RequestException as e:
            print(f"[!] Request failed for {url}: {e}")

        return None

    def fuzzParams(self):
        """
            Fuzz query params
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
                fuzzedQuery = originalQuery.replace("FUZZ", payload)

                fullUrl = f"{baseNoQuery}?{fuzzedQuery}"

                tasks.append(executor.submit(self.sendRequest, fullUrl, 0, isParamFuzzing=True, payload= payload))

            for future in as_completed(tasks):
                result = future.result()
                if result:
                    results.append(result)
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
            # print("[+] Logged in to DVWA and set security level to low")

            return True

        except requests.RequestException as e:
            print(f"[!] Login request failed: {e}")
            return False

    def run(self,fuzzParams= True, fuzzPaths=True):
        """
        Main entry to run fuzzing
        """

        paths, endpoints = self.getInitalPaths()
        results = []

        # If any endpoints with query params exist FUZZ
        if fuzzParams:
            for ep in endpoints:
                if ep["params"]:
                    paramResults = self.fuzzParams()
                    results.extend(paramResults)

        # Fuzz discovered or base paths
        if fuzzPaths:
            for path in paths:
                # For debugging
                # print(f"Fuzzing: {path}")
                self.fuzzPath(path)

        combined = results + [
            {"url": result["url"], "payload": result["payload"], "type": "path"}
            for result in self.vulnerablePaths
        ]

        # Remove dups
        seen = set()
        uniqueResults = []

        for r in combined:
            key = (r["type"], r["url"], r["payload"])
            if key not in seen:
                seen.add(key)
                uniqueResults.append(r)

        return uniqueResults


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
        isDVWA=args.dvwa,
        isSilent=True
    )

    results = fuzzer.run(fuzzParams=args.fuzz_params, fuzzPaths=args.fuzz_paths)

    if results:
        print("\n[+] Vulnerabilities discovered:")

        for vuln in results:
            print(f"  - Type: {vuln['type'].upper()}, URL: {vuln['url']}, Payload: {vuln['payload']}")

        if args.output_to_file:
            with open("pathFuzzerOutput.txt", "w") as f:
                for vuln in results:
                    f.write(f"{vuln['type'].upper()} | {vuln['url']} | Payload: {vuln['payload']}\n")

    else:
        print("[-] No vulnerabilities found.")


