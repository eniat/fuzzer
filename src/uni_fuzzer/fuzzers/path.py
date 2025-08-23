import requests
import re
import threading
from urllib.parse import urljoin, urlparse, parse_qs, urldefrag
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import PurePosixPath
from difflib import SequenceMatcher

from uni_fuzzer.auth.auth import login

from uni_fuzzer.core.utility import get_cfg
cfg = get_cfg()

MAX_SAMPLES_PER_GROUP = cfg["path_traversal"]["max_samples_per_group"]

class PathFuzzer:

    def __init__(self, baseUrl, wordlistPath= None, outputToFile = False, maxDepth= None,isSilent= False, loginUsername=None,loginPassword=None, loginPath=None, session =None, auth= None):
        self.baseUrl = baseUrl
        self.wordlistPath = wordlistPath
        self.outputToFile = outputToFile
        self.maxDepth =  maxDepth if maxDepth is not None else cfg["fuzz"]["max_depth_default"]
        self.payloads = self.loadWordlist()
        self.isSilent = isSilent

        # Authentication
        self.session = session or requests.Session()
        self.loginUsername = loginUsername
        self.loginPassword = loginPassword
        self.loginPath = loginPath
        self.auth = auth

        # results storage
        self.visitedPaths = set()
        self.visitedFuzzPaths = set()
        self.vulnerablePaths = {}
        self.lock = threading.Lock()

        # Below set in config/defaults.yaml
        self.indicators = cfg["path_traversal"]["indicators"]

        self.headers = {"User-Agent": cfg["http"]["user_agent"]}
        if cfg["http"]["add_referer"]:
            self.headers["Referer"] = self.baseUrl

        self.excludedExtensions = cfg["fuzz"]["excluded_extensions"]

        if self.auth and self.loginUsername and self.loginPassword:
            ok = login(self.session, self.baseUrl, self.loginUsername, self.loginPassword, self.loginPath)
            if not ok :
                print("[-] HTTP login in PathFuzzer failed")

        self.baseline = self.getBaseline()


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
        except Exception as e :
            # On error raise exception
            raise RuntimeError( f"[-] Failed to load wordlist from {self.wordlistPath}: {e}")

    def isPathTraversalSuccess(self, response, url):
        """
            Detect success based on response
        """
        content = response.text.lower()
        status = response.status_code

        # Check for indicators in response
        for indicator in self.indicators:
            if re.search(rf'\b{re.escape(indicator)}\b', content):
                #print(f"[DEBUG] Matched indicator '{indicator}' in response from {url}")
                return "vulnerable", indicator

        # If 200 but no indicators deem interesting
        if status == 200:
            return "interesting", None

        return "none", None

    def  fuzzPath(self, path, currDepth= 0):
        """
            Fuzz the URL path using the payload
        """
        segments = path.strip("/").split("/")
        # Shorten the path if it ends with one of the self.excludedExtensions
        for i, segment in enumerate(segments):
            if any(segment.endswith(ext) for ext in self.excludedExtensions):
                path = "/" if i == 0 else "/" + "/".join(segments[:i])
                break

        normalizedPath = str(PurePosixPath(path))
        if normalizedPath != "/" and normalizedPath.endswith("/"):
            normalizedPath = normalizedPath.rstrip("/")

        with self.lock:
            if normalizedPath in self.visitedFuzzPaths:
                return
            self.visitedFuzzPaths.add(normalizedPath)

        if currDepth > self.maxDepth:
            return

        tasks = []
        interestingResults  = []

        parsed = urlparse(self.baseUrl)
        base = f"{parsed.scheme}://{parsed.netloc}"

        with ThreadPoolExecutor(max_workers=cfg["concurrency"]["max_workers"]) as executor:
            # Fuzz with all payloads
            for payload in self.payloads:
                # Check for /
                basePath = path if path.endswith('/') else path + '/'
                fullPath = basePath + payload

                normalizedPayloadPath = PurePosixPath(fullPath).as_posix().rstrip("/") or "/"

                with self.lock:
                    if normalizedPayloadPath in self.visitedPaths:
                        continue
                    self.visitedPaths.add(normalizedPayloadPath)

                targetUrl = f"{base}/{fullPath.lstrip('/')}"

                tasks.append(executor.submit( self.sendRequest, targetUrl, currDepth,isParamFuzzing= False, payload =payload))

            for future in as_completed(tasks):
                result  = future.result()
                if result and result["type"] == "interesting":
                    interestingResults.append((
                        result["data"]["url"],
                        result["data"]["depth"]))

        with ThreadPoolExecutor(max_workers=cfg["concurrency"]["path_workers_recursive"]) as executor:
            # Recurse on new 200 paths that are interesting
            futures = []
            for (interestingPath, nextDepth) in interestingResults:
                normalized = PurePosixPath(interestingPath).as_posix().rstrip("/") or "/"

                with self.lock:
                    if normalized in self.visitedFuzzPaths:
                        # if not self.isSilent:
                        #     #print(f"[DEBUG] Skipping recursive interesting path: {normalized}")
                        continue

                    self.visitedFuzzPaths.add(normalized)
                futures.append(executor.submit(self.fuzzPath, interestingPath, nextDepth))

            for future in as_completed(futures):
                future.result()

    def sendRequest(self, url, depth, isParamFuzzing= False,payload= None):
        """
            Send a single GET request and check for success
        """
        try:

            response = self.session.get(url, headers=self.headers, timeout=cfg["http"]["timeout_get_seconds"], allow_redirects=cfg["http"]["redirects"]["fuzz_get"])

            resultType, indicator = self.isPathTraversalSuccess(response,url)
            status = response.status_code

            if resultType == "interesting" and not isParamFuzzing and self.baseline:

                baselineText = self.baseline["content"]
                responseText = response.text
                similarity = SequenceMatcher(None, baselineText, responseText).quick_ratio()

                # If too similar skip as false positive
                if status == self.baseline["status_code"] and similarity >= cfg["fuzz"]["similarity_skip_threshold"]:
                    # if not self.isSilent:
                    #     print(f"[i] Skipping 200 based on similarity ({similarity:.2f}): {url}")
                    return None

                elif status == 200 and similarity < cfg["fuzz"]["similarity_skip_threshold"]:
                    # if not self.isSilent:
                    #     print(f"[+]Discovered interesting path: {url} (Similarity: {similarity:.2f})")

                    result= {"url": urlparse(url).path,
                             "depth": depth + 1,
                             "status_code": status,
                             "payload": payload,
                             "response_snippet": response.text[:200],
                             "type": "interesting_200"
                             }

                    return {"type": "interesting_200", "data": result}

            if resultType == "vulnerable":
                with self.lock:
                    kind = "param" if isParamFuzzing else "path"
                    pageKey = (url if isParamFuzzing else urlparse(url).path).split("?", 1)[0].split("#", 1)[0]
                    resultsKey = (pageKey, indicator or "N/A", kind)

                    # First timer
                    if resultsKey not in self.vulnerablePaths:
                        self.vulnerablePaths[resultsKey] = {
                            "url": pageKey,
                            "payload": payload,
                            "payload_samples": [payload] if payload else [],
                            "status_code": response.status_code,
                            "indicator": indicator or "N/A",
                            "snippet": (response.text or "")[:200],
                            "count": 1,
                            "type": kind,
                        }

                    else:
                        entry = self.vulnerablePaths[resultsKey]
                        entry["count"] += 1

                        if payload and len(entry["payload_samples"]) < MAX_SAMPLES_PER_GROUP:
                            entry["payload_samples"].append(payload)

                    return {"type": "vulnerable", "data": self.vulnerablePaths[resultsKey]}

            elif resultType == "interesting" and not isParamFuzzing:

                #Prevent recursion on files
                parsed = urlparse(url).path.lower()

                if any(parsed.endswith(ext) for ext in self.excludedExtensions) or '.php/' in parsed:
                    return None

                return {
                    "type": "interesting",
                    "data": {
                        "url": urlparse(url).path,
                        "depth": depth + 1,
                        "status_code": status,
                        "payload": payload
                    }
                }

        except requests.exceptions.Timeout:
            # When fuzzing large endpoints timeouts overwhelm, disable if needed
            pass

        except requests.RequestException as e:
            if not self.isSilent:
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

        with ThreadPoolExecutor(max_workers=cfg["concurrency"]["max_workers"]) as executor:
            for payload in self.payloads:
                # Replace FUZZ with the payload
                fuzzedQuery = originalQuery.replace("FUZZ", payload)

                fullUrl = f"{baseNoQuery}?{fuzzedQuery}"

                tasks.append(executor.submit(self.sendRequest, fullUrl, 0, isParamFuzzing=True, payload= payload))

            for future in as_completed(tasks):
                _ = future.result()

        grouped = [v for (k_url, k_ind, k_kind), v in self.vulnerablePaths.items() if k_kind == "param"]
        return grouped


    def getBaseline(self):
        """
            Help path fuzzing with false positives
        """
        testPath = cfg["fuzz"]["baseline_404_path"]
        testUrl = urljoin(self.baseUrl, testPath)

        try:
            res = self.session.get(testUrl, headers=self.headers, timeout=cfg["http"]["timeout_get_seconds"], allow_redirects=cfg["http"]["redirects"]["baseline_get"])
            return {
                "status_code": res.status_code,
                "content": res.text
            }
        except Exception as e:
            if not self.isSilent:
                print( f"[!] Could not get baseline signature:{e}")
            return None
