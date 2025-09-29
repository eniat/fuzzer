import threading
import logging
from urllib.parse import urlparse, quote
from pathlib import PurePosixPath

from uni_fuzzer.core.base_fuzzer import AbstractFuzzer
from uni_fuzzer.core.reporting import Finding
from uni_fuzzer.fuzzers.detection import detectPathTraversal
from uni_fuzzer.core.baseline import getBaseline
from uni_fuzzer.auth.auth import login
from uni_fuzzer.core.utility import get_cfg, loadWordlist, status
cfg = get_cfg()

log = logging.getLogger(__name__)

class PathFuzzer(AbstractFuzzer):

    def __init__(self, baseUrl, wordlistPath=None, maxDepth=None, loginUsername=None, loginPassword=None,loginPath=None, session=None, auth=None, bailEvent=None):

        super().__init__(baseUrl=baseUrl, session=session, wordlistPath=wordlistPath, bailEvent=bailEvent, cfg=cfg)

        self.maxDepth =  maxDepth if maxDepth is not None else self.cfg["fuzz"]["max_depth_default"]
        self.payloads = loadWordlist(self.wordlistPath) if self.wordlistPath is not None else []
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

        self.headers = {"User-Agent": self.cfg["http"]["user_agent"]}
        if self.cfg["http"]["add_referer"]:
            self.headers["Referer"] = self.baseUrl

        self.excludedExtensions = self.cfg["fuzz"]["excluded_extensions"]

        if self.auth and self.loginUsername and self.loginPassword:
            ok = login(self.session, self.baseUrl, self.loginUsername, self.loginPassword, self.loginPath)
            if not ok :
                status("[!] HTTP login in PathFuzzer failed")
                log.warning("HTTP login in PathFuzzer failed")

        self.baseline = None

    def prepare(self, ctx):
        self.baseline = getBaseline(self.session, self.baseUrl, self.headers)

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

        parsed = urlparse(self.baseUrl)
        base = f"{parsed.scheme}://{parsed.netloc}"

        batch = []

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
            meta = {"payload": payload, "depth": currDepth, "kind": "path"}
            batch.append(("GET", targetUrl, {"headers": self.headers}, meta))

        self.prepare(None) if self.baseline is None else None
        # Execute via base helper
        findings = self.runBatch(batch, concurrency=self.cfg["concurrency"]["max_workers"])

        # Pick up interesting_200 and recurse
        interestingResults = []
        for find in findings:
            if getattr(find, "type", None) == "interesting_200":
                url = find.url
                parse = urlparse(url)
                interestingResults.append((parse.path or "/", (currDepth + 1)))

        if self.bailEvent and self.bailEvent.is_set():
            return

        for (interestingPath, nextDepth) in interestingResults:
            normalized = PurePosixPath(interestingPath).as_posix().rstrip("/") or "/"

            with self.lock:
                if normalized in self.visitedFuzzPaths:
                    continue

                self.visitedFuzzPaths.add(normalized)
            self.fuzzPath(interestingPath, nextDepth)


    def analyzeResponse(self, response, meta):
        """
            Analyze the responses and return findings
        """
        resultType, indicator = detectPathTraversal(response, self.baseline)
        statusC = response.status_code
        meta = meta or {}
        payload = meta.get("payload")

        # Skip if too similar
        if resultType == "skip_similar":
            return None

        params = ("?" in (response.url or "")) or (meta.get("kind") == "params")

        # If an interesting_200 then add to results and recurse
        if resultType == "interesting_200":
            result = Finding(
                type="interesting_200",
                url=response.url,
                method="GET",
                payload=payload,
                status_code=statusC,
                response_snippet=(response.text or "")[:200]
            )
            with self.lock:
                self.interesting200.append(result)

            return result

        # If an interesting then add to results
        if resultType == "interesting":
            res = Finding(
                type="interesting",
                url=response.url,
                method="GET",
                payload=payload,
                status_code=statusC,
                indicator=indicator
            )
            with self.lock:
                self.interesting.append(res)
            return res

        # If vulnerability hit add to results
        if resultType == "vulnerable":
            # First timer
            resType = "param" if params else "path"
            res = Finding(
                type=resType,
                url=response.url,
                method="GET",
                payload=payload,
                status_code=statusC,
                indicator=indicator
            )
            with self.lock:
                key = (response.url.split("?", 1)[0], indicator, resType)
                self.vulnerablePaths[key] = res
            return res

        return None

    def fuzzParams(self):
        """
            Fuzz query params
        """
        parsed = urlparse(self.baseUrl)

        if "FUZZ" not in parsed.query:
            status("[-] No 'FUZZ' keyword found")
            return []

        baseNoQuery = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        originalQuery = parsed.query

        batch = []

        for raw in self.payloads:
            if self.bailEvent and self.bailEvent.is_set():
                break
            enc = quote(raw, safe="")
            # Replace FUZZ with the payload
            fuzzedQuery = originalQuery.replace("FUZZ", enc)

            fullUrl = f"{baseNoQuery}?{fuzzedQuery}"

            meta = {"payload": raw, "kind": "params"}
            batch.append(("GET", fullUrl, {"headers": self.headers}, meta))

        if self.baseline is None:
            self.prepare(None)

        # Execute via base helper
        findings = self.runBatch(batch, concurrency=self.cfg["concurrency"]["max_workers"])
        # Return only confirmed param vulns
        return [f for f in findings if getattr(f, "type", "") == "param"]


