import threading
import logging
from urllib.parse import urlparse
from pathlib import PurePosixPath

from ..core.baseline import getBaseline

from ..runtime.context import AppContext
from ..core.base_fuzzer import AbstractFuzzer
from ..core.reporting import Finding

log = logging.getLogger(__name__)


class TraversalPathFuzzer(AbstractFuzzer):
    """
        Fuzz the URL path using the payload
    """

    def __init__(self, baseUrl, wordlistPath=None, maxDepth=None, loginUsername=None, loginPassword=None,loginPath=None, session=None, auth=None, bailEvent=None,cfg=None, ctx: AppContext | None = None):

        super().__init__(baseUrl=baseUrl, session=session, wordlistPath=wordlistPath, bailEvent=bailEvent, cfg=cfg)
        self.ctx = ctx
        if self.ctx is None:
            raise ValueError("Path Fuzzer requires an AppContext")

        self.maxDepth =  maxDepth if maxDepth is not None else self.cfg["fuzz"]["max_depth_default"]
        self.payloads = self.ctx.util.load_wordlist(self.wordlistPath) if self.wordlistPath is not None else []
        self.auth = auth
        self.loginUsername = loginUsername
        self.loginPassword = loginPassword
        self.loginPath = loginPath

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
            ok = self.ctx.auth.http_login(self.session, self.baseUrl, self.loginUsername, self.loginPassword, self.loginPath)
            if not ok :
                self.ctx.util.status("[!] HTTP login in TraversalPathFuzzer  failed")
                log.warning("HTTP login in TraversalPathFuzzer  failed")

        self.baseline = None

    def prepare(self, ctx):
        if self.baseline is None:
            self.baseline = getBaseline(self.session, self.baseUrl, self.headers)

    def  run(self, ctx=None, path=None, currDepth=0):
        """
            Fuzz the URL path using the payload
        """

        if path is None:
            p = urlparse(self.baseUrl).path
            path = p if p else "/"
            currDepth = 0

        if self.baseline is None:
            self.prepare(None)

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
                return []
            self.visitedFuzzPaths.add(normalizedPath)

        # If bail on first then bail
        if self.bailEvent and self.bailEvent.is_set():
            return []

        if currDepth > self.maxDepth:
            return []

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

        # Execute via base helper
        findings = self.runBatch(batch, concurrency=self.cfg["concurrency"]["max_workers"])
        results = list(findings)

        # Pick up interesting_200 and recurse
        interestingResults = []
        for find in findings:
            if getattr(find, "type", None) == "interesting_200":
                url = find.url
                parse = urlparse(url)
                interestingResults.append((parse.path or "/", (currDepth + 1)))

        if self.bailEvent and self.bailEvent.is_set():
            return results

        for (interestingPath, nextDepth) in interestingResults:
            normalized = PurePosixPath(interestingPath).as_posix().rstrip("/") or "/"

            with self.lock:
                if normalized in self.visitedFuzzPaths:
                    continue

                self.visitedFuzzPaths.add(normalized)
            child = self.run(None, interestingPath, nextDepth)
            if child:
                results.extend(child)

        return results


    def analyzeResponse(self, response, meta):
        """
            Analyze the responses and return findings
        """
        resultType, indicator = self.ctx.dete.detect_path_traversal(response, self.baseline)
        statusC = response.status_code
        meta = meta or {}
        payload = meta.get("payload")

        # Skip if too similar
        if resultType == "skip_similar":
            return None

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
            setattr(result, "bail", False)
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
            setattr(res, "bail", False)
            with self.lock:
                self.interesting.append(res)
            return res

        # If vulnerability hit add to results
        if resultType == "vulnerable":
            # First timer
            resType = "path"
            res = Finding(
                type=resType,
                url=response.url,
                method="GET",
                payload=payload,
                status_code=statusC,
                indicator=indicator
            )
            setattr(res, "bail", True)
            with self.lock:
                key = (response.url.split("?", 1)[0], indicator, resType)
                self.vulnerablePaths[key] = res
            return res

        return None