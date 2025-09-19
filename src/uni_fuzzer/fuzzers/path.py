import requests
import threading
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import PurePosixPath

from requests.adapters import HTTPAdapter

from uni_fuzzer.fuzzers.detection import detectPathTraversal
from uni_fuzzer.core.baseline import getBaseline
from uni_fuzzer.auth.auth import login
from uni_fuzzer.core.utility import get_cfg, loadWordlist
cfg = get_cfg()

MAX_SAMPLES_PER_GROUP = cfg["path_traversal"]["max_samples_per_group"]

class PathFuzzer:

    def __init__(self, baseUrl, wordlistPath= None, outputToFile = False, maxDepth= None,loginUsername=None,loginPassword=None, loginPath=None, session =None, auth= None,bailEvent=None):
        self.baseUrl = baseUrl
        self.wordlistPath = wordlistPath
        self.outputToFile = outputToFile
        self.maxDepth =  maxDepth if maxDepth is not None else cfg["fuzz"]["max_depth_default"]
        self.payloads = loadWordlist(self.wordlistPath) if self.wordlistPath is not None else []
        self.bailEvent = bailEvent

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

        # results storage
        self.visitedPaths = set()
        self.visitedFuzzPaths = set()
        self.vulnerablePaths = {}
        self.lock = threading.Lock()
        self.interesting200 = []
        self.interesting = []

        self.headers = {"User-Agent": cfg["http"]["user_agent"]}
        if cfg["http"]["add_referer"]:
            self.headers["Referer"] = self.baseUrl

        self.excludedExtensions = cfg["fuzz"]["excluded_extensions"]

        if self.auth and self.loginUsername and self.loginPassword:
            ok = login(self.session, self.baseUrl, self.loginUsername, self.loginPassword, self.loginPath)
            if not ok :
                print("[-] HTTP login in PathFuzzer failed")

        self.baseline = getBaseline(self.session, baseUrl, self.headers)

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

        # If bail on first then bail
        if self.bailEvent and self.bailEvent.is_set():
            return

        if currDepth > self.maxDepth:
            return

        tasks = []
        interestingResults  = []

        parsed = urlparse(self.baseUrl)
        base = f"{parsed.scheme}://{parsed.netloc}"

        with ThreadPoolExecutor(max_workers=cfg["concurrency"]["max_workers"]) as executor:
            # Fuzz with all payloads
            for payload in self.payloads:
                # If bail on first then bail
                if self.bailEvent and self.bailEvent.is_set():
                    break
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
                if result and result["type"] == "interesting_200":
                    interestingResults.append((
                        result["data"]["url"],
                        result["data"]["depth"]))
        # If bail on first then bail
        if self.bailEvent and self.bailEvent.is_set():
            return
        with ThreadPoolExecutor(max_workers=cfg["concurrency"]["path_workers_recursive"]) as executor:
            # Recurse on new 200 paths that are interesting
            futures = []
            for (interestingPath, nextDepth) in interestingResults:
                normalized = PurePosixPath(interestingPath).as_posix().rstrip("/") or "/"

                with self.lock:
                    if normalized in self.visitedFuzzPaths:
                        continue

                    self.visitedFuzzPaths.add(normalized)
                futures.append(executor.submit(self.fuzzPath, interestingPath, nextDepth))

            for future in as_completed(futures):
                future.result()

    def sendRequest(self, url, depth, isParamFuzzing= False,payload= None):
        """
            Send a GET request and check for success
        """
        try:
            # If bail on first then bail
            if self.bailEvent and self.bailEvent.is_set():
                return
            response = self.session.get(url, headers=self.headers, timeout=cfg["http"]["timeout_get_seconds"], allow_redirects=cfg["http"]["redirects"]["fuzz_get"])

            resultType, indicator = detectPathTraversal(response,self.baseline)
            status = response.status_code

            # Skip if too similar
            if resultType == "skip_similar":
                return None

            # If an interesting_200 then add to results
            if resultType == "interesting_200" and not isParamFuzzing:
                result = {
                    "url": url,
                    "depth": depth + 1,
                    "status_code": status,
                    "payload": payload,
                    "response_snippet": (response.text or "")[:200],
                    "type": "interesting_200"
                }
                with self.lock:
                    self.interesting200.append(result)

                return {"type": "interesting_200", "data": result}

            if resultType == "vulnerable":
                with self.lock:
                    kind = "param" if isParamFuzzing else "path"
                    pageKey = (url if isParamFuzzing else urlparse(url).path).split("?", 1)[0].split("#", 1)[0]

                    resultsKey = (pageKey, indicator or "N/A", kind)

                    # First timer
                    if resultsKey not in self.vulnerablePaths:
                        self.vulnerablePaths[resultsKey] = {
                            "url": url,
                            "payload": payload,
                            "payload_samples": [payload] if payload else [],
                            "status_code": response.status_code,
                            "indicator": indicator or "N/A",
                            "snippet": (response.text or "")[:200],
                            "count": 1,
                            "type": kind,
                        }

                        if self.bailEvent:
                            try:
                                self.bailEvent.set()
                            except Exception:
                                pass

                    else:
                        entry = self.vulnerablePaths[resultsKey]
                        entry["count"] += 1

                        if payload and len(entry["payload_samples"]) < MAX_SAMPLES_PER_GROUP:
                            entry["payload_samples"].append(payload)

                    return {"type": "vulnerable", "data": self.vulnerablePaths[resultsKey]}

            elif resultType == "interesting" and not isParamFuzzing:

                with self.lock:
                    self.interesting.append({
                        "url": url,
                        "depth": depth + 1,
                        "status_code": status,
                        "payload": payload,
                        "type": "interesting"
                    })

                #Prevent recursion on files
                parsed = urlparse(url).path.lower()

                if any(parsed.endswith(ext) for ext in self.excludedExtensions) or '.php/' in parsed:
                    return None

                return {
                    "type": "interesting",
                    "data": {
                        "url": url,
                        "depth": depth + 1,
                        "status_code": status,
                        "payload": payload
                    }
                }

        except requests.exceptions.Timeout:
            # When fuzzing large endpoints timeouts overwhelm, disable if needed
            pass

        except Exception:
            pass

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

