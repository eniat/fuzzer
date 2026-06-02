import logging

from urllib.parse import urlparse, quote, unquote_plus
from uuid import uuid4
from html import unescape

from ..runtime.context import AppContext
from ..core.base_fuzzer import AbstractFuzzer
from ..core.reporting import Finding

log = logging.getLogger(__name__)

class ParamXSSFuzzer(AbstractFuzzer):
    """
        Fuzz query params for reflected XSS
    """
    name: str = "xss_param"

    def __init__(self, baseUrl, wordlistPath=None,session=None, bailEvent=None, cfg=None,auth=False, loginUsername=None,loginPassword=None, loginPath=None, token=None, headers=None, ctx: AppContext | None = None):
        super().__init__(baseUrl=baseUrl, session=session, headers=headers, wordlistPath=wordlistPath, bailEvent=bailEvent, cfg=cfg)
        self.ctx=ctx
        if self.ctx is None:
            raise ValueError("XSS Param Fuzzer requires an AppContext")

        if self.cfg["http"]["add_referer"]:
            self.headers["Referer"] = self.baseUrl


        self.payloads = self.ctx.util.load_wordlist(self.wordlistPath) if self.wordlistPath is not None else []
        self.token = token or f"XSSCanary-{uuid4().hex[:8]}"
        self.tokenB = self.token.encode("utf-8", errors="ignore")

        self.auth = auth
        self.loginUsername = loginUsername
        self.loginPassword = loginPassword
        self.loginPath = loginPath

        self.ready = False
        self.reflective = False
        self.baseNoQuery = None
        self.originalQuery = None
        self.prebuiltPayloads = []

        if self.auth and self.loginUsername and self.loginPassword:
            # Use the generic HTTP login in auth.py
            ok = self.ctx.auth.http_login(
                self.session,
                start_url=self.baseUrl,
                username=self.loginUsername,
                password=self.loginPassword,
                login_path=self.loginPath,
                selectors=None,
                headers=None
            )
            if not ok:
                self.ctx.util.status("[!] HTTP login in XSSFuzzer failed")
                log.warning("HTTP login in XSSFuzzer failed")

    def prepare(self, ctx):
        """
            Check FUZZ in in query, build payloads and probe reflexivity
        """

        self.prebuiltPayloads = []
        self.ready = False
        self.reflective = False
        parsed = urlparse(self.baseUrl)

        # Only fuzz if fuzz in query
        if "FUZZ" not in parsed.query:
            self.ctx.util.status("[-] No 'FUZZ' keyword found")
            log.info("No 'FUZZ' keyword found in query for %s", self.baseUrl)
            self.ready= True
            return

        # Reconstruct base URL without query
        self.baseNoQuery = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        self.originalQuery = parsed.query

        seen = set()
        for raw in self.payloads:
            if raw in seen:
                continue

            seen.add(raw)
            marked = self.ctx.util.canary(raw, self.token)
            enc = quote(marked, safe="")
            self.prebuiltPayloads.append((raw, marked, enc))

        # Singular probe to check if reflective
        probe = f"xssprobe-{self.token}"
        probeQuery = self.originalQuery.replace("FUZZ", quote(probe, safe=""))
        probeUrl = f"{self.baseNoQuery}?{probeQuery}"
        plow = probe.lower()

        try:
            res = self.session.get(
                probeUrl,
                headers=self.headers,
                timeout=self.cfg["http"]["timeout_get_seconds"],
                allow_redirects=False
            )
            body = res.text or ""
            bodyLow = body.lower()
            if (plow not in bodyLow) and (unescape(body).lower().find(plow) == -1):
                log.debug("Probe not reflected for %s", probeUrl)
                self.reflective = False
                return
            self.reflective = True
            self.ready = True

        except Exception:
            log.debug("Probe request failed for %s", probeUrl, exc_info=True)
            self.reflective = False
            self.ready = True


    def run(self, ctx=None):
        """
            Build batch and execute via runBatch
        """

        if not self.ready:
            self.prepare(None)

        if not self.reflective:
            # If not reflective no need to fuzz
            return []

        batch = []

        for raw, marked, enc in self.prebuiltPayloads:
            # If bail on first then bail
            if self.bailEvent and self.bailEvent.is_set():
                break
            # Replace FUZZ with the payload, uniquely mark it, encode it for URL injection
            fuzzedQuery = self.originalQuery.replace("FUZZ", enc)
            fullUrl = f"{self.baseNoQuery}?{fuzzedQuery}"

            meta ={
                "kind": "xss_param",
                "payload": raw,
                "marked": marked
            }

            batch.append(("GET", fullUrl, {"headers": self.headers, "allow_redirects": False}, meta))

        findings = self.runBatch(batch, concurrency=self.cfg["concurrency"]["max_workers"])

        return findings


    def analyzeResponse(self, response, meta):
        """
            analyze the response for reflected XSS
        """

        # Skip non-HTML, xml and javascript
        ctype = (response.headers.get("Content-Type") or "").lower()
        if ctype and all(t not in ctype for t in ("html", "xml", "javascript", "svg")):
            return None

        # If token bytes not present skip
        content = response.content or b""
        if self.tokenB not in content:
            return None

        enc = response.encoding or "utf-8"

        # Detect XSS with detect function
        marked = (meta or {}).get("marked")

        # makes sure that the exact marked payload is reflected
        body = content.decode(enc, errors="ignore")
        low = body.lower()
        lowU = unescape(body).lower()
        lowQ = unquote_plus(body).lower()

        if marked:
            mlow = marked.lower()
            if mlow not in low and mlow not in lowU and mlow not in lowQ:
                return None

        ok, indicator = self.ctx.dete.detect_xss(body, self.token)

        if not ok:
            return None

        payload = (meta or {}).get("payload")
        finding = Finding(
            type="xss_param",
            url=response.url,
            method="GET",
            payload=payload,
            indicator=(indicator or "N/A"),
            status_code=response.status_code,
            response_snippet=body[:200],
        )
        setattr(finding, "bail", True)
        return finding
