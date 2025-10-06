import threading
import logging

from urllib.parse import urlparse, quote

from ..runtime.context import AppContext
from ..core.base_fuzzer import AbstractFuzzer
from ..core.reporting import Finding

log = logging.getLogger(__name__)

class ParamPathFuzzer(AbstractFuzzer):
    """
        Fuzz query params
    """

    def __init__(self, baseUrl, wordlistPath=None, loginUsername=None, loginPassword=None,loginPath=None, session=None, auth=None, bailEvent=None,cfg=None, ctx: AppContext | None = None):

        super().__init__(baseUrl=baseUrl, session=session, wordlistPath=wordlistPath, bailEvent=bailEvent, cfg=cfg)
        self.ctx = ctx
        if self.ctx is None:
            raise ValueError("Param Fuzzer requires an AppContext")

        self.payloads = self.ctx.util.load_wordlist(self.wordlistPath) if self.wordlistPath is not None else []
        self.auth = auth
        self.loginUsername = loginUsername
        self.loginPassword = loginPassword
        self.loginPath = loginPath

        # results storage
        self.vulnerablePaths = {}
        self.lock = threading.Lock()

        self.headers = {"User-Agent": self.cfg["http"]["user_agent"]}
        if self.cfg["http"]["add_referer"]:
            self.headers["Referer"] = self.baseUrl

        if self.auth and self.loginUsername and self.loginPassword:
            ok = self.ctx.auth.http_login(self.session, self.baseUrl, self.loginUsername, self.loginPassword, self.loginPath)
            if not ok :
                self.ctx.util.status("[!] HTTP login in ParamPathFuzzer  failed")
                log.warning("HTTP login in ParamPathFuzzer  failed")

        self.baseline = None


    def prepare(self, ctx):
        if self.baseline is None:
            self.baseline = self.ctx.base.get_baseline(self.session, self.baseUrl, self.headers)


    def run(self, ctx=None):
        """
            Fuzz query params
        """
        parsed = urlparse(self.baseUrl)

        if "FUZZ" not in parsed.query:
            self.ctx.util.status("[-] No 'FUZZ' keyword found")
            return []

        if not self.payloads:
            return []

        if self.baseline is None:
            self.prepare(None)

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

        # Execute via base helper
        findings = self.runBatch(batch, concurrency=self.cfg["concurrency"]["max_workers"])

        return findings


    def analyzeResponse(self, response, meta):
        """
            Analyze the responses and return findings
        """
        resultType, indicator = self.ctx.dete.detect_path_traversal(response, self.baseline)

        if resultType != "vulnerable":
            return None

        meta = meta or {}
        payload = meta.get("payload")

        # If vulnerability hit add to results
        res = Finding(
            type="param",
            url=response.url,
            method="GET",
            payload=payload,
            status_code=response.status_code,
            indicator=indicator
        )
        with self.lock:
            key = (response.url.split("?", 1)[0], indicator, "param")
            self.vulnerablePaths[key] = res
        setattr(res, "bail", True)
        return res
