import logging

from urllib.parse import urljoin, urlparse, quote, unquote_plus
from uuid import uuid4
from html import unescape

from ..core.baseline import baselineForm

from ..runtime.context import AppContext
from ..core.base_fuzzer import AbstractFuzzer
from ..core.reporting import Finding

log = logging.getLogger(__name__)

class StoredXSSFuzzer(AbstractFuzzer):
    """
        Submits payload then revisits to see if payload still there
    """

    def __init__(self, baseUrl, wordlistPath=None, session=None, bailEvent=None, cfg=None, auth=False, loginUsername=None, loginPassword=None, loginPath=None, token=None, headers=None, ctx: AppContext | None = None):
        super().__init__(baseUrl=baseUrl, session=session, headers=headers, wordlistPath=wordlistPath, bailEvent=bailEvent, cfg=cfg)
        self.ctx = ctx
        if self.ctx is None:
            raise ValueError("XSS Stored Fuzzer requires an AppContext")

        if self.cfg["http"]["add_referer"]:
            self.headers["Referer"] = self.baseUrl

        self.payloads = self.ctx.util.load_wordlist(self.wordlistPath) if self.wordlistPath is not None else []
        self.token = token or f"XSSCanary-{uuid4().hex[:8]}"
        self.tokenB = self.token.encode("utf-8", errors="ignore")

        self.auth = auth
        self.loginUsername = loginUsername
        self.loginPassword = loginPassword
        self.loginPath = loginPath

        self.prepared = False
        self.prebuiltPayloads = []
        self.reported = set()

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
            Build payloads
        """

        if self.prepared:
            return

        # Prebuilding to remove multiple canary and quote calls
        self.prebuiltPayloads = []
        seen = set()

        for raw in self.payloads:
            if raw in seen:
                continue

            seen.add(raw)
            marked = self.ctx.util.canary(raw, self.token)
            enc = quote(marked, safe="")
            self.prebuiltPayloads.append((raw, marked, enc))

        self.prepared = True


    def run(self, ctx):
        """
            Build batch and execute via runBatch
        """
        self.reported.clear()
        pages = []

        if isinstance(ctx, dict):
            forms = ctx.get("forms")
        else:
            forms = getattr(ctx, "forms", None)

        if not self.prepared:
            self.prepare(None)

        parsed = urlparse(self.baseUrl)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Submit part

        batch = []
        for form in (forms or []):
            # If bail on first then bail
            if self.bailEvent and self.bailEvent.is_set():
                break

            url = form.get("url")
            method = (form.get("method") or "POST").upper()
            fields = form.get("formFields") or []

            if not url or not fields:
                log.debug("Skipping invalid form (url/fields missing): %s", form)
                continue

            if not url.startswith("http"):
                url = f"{origin}{url}"

            fuzzFields = [f for f in fields if self.ctx.util.is_fuzzable_field(f)]

            if not fuzzFields:
                log.debug("No fuzzable fields for form %s", url)
                continue

            # Get baseline to check for submit buttons
            try:
                base = baselineForm(self.session, url, self.headers)
                baseHtml = base.get("content") or ""
            except Exception:
                log.debug("baselineForm failed for %s", url, exc_info=True)
                baseHtml = ""

            # Track the form to potentially revisit
            if url not in pages:
                pages.append(url)

            if method == "POST":
                # POST form fuzzing
                baseD = {f: "test" for f in fields}
                baseD = self.ctx.util.auto_submits(baseHtml, baseD)
                for raw, marked, enc in self.prebuiltPayloads:
                    # If bail on first then bail
                    if self.bailEvent and self.bailEvent.is_set():
                        break
                    data = dict(baseD)
                    for f in fuzzFields:
                        data[f] = marked

                    meta = {"phase": "submit", "kind": "xss_stored_submit",
                            "payload": raw, "marked": marked,
                            "submit_method": "POST", "origin_url": url}

                    batch.append(("POST", url,{"headers": self.headers,"data": data,
                                          "allow_redirects": self.cfg["http"]["redirects"]["submit"]}, meta))

            else:
                # GET form fuzzing
                baseP = {f: "test" for f in fields}
                separator = "&" if "?" in url else "?"
                for raw, marked, enc in self.prebuiltPayloads:
                    # If bail on first then bail
                    if self.bailEvent and self.bailEvent.is_set():
                        break
                    params = dict(baseP)
                    for f in fuzzFields:
                        params[f] = enc

                    logParams = [f"{k}={v}" for k, v in params.items()]
                    fullUrl = f"{url}{separator}{'&'.join(logParams)}"

                    meta = {"phase": "submit", "kind": "xss_stored_submit",
                            "payload": raw, "marked": marked,
                            "submit_method": "GET", "origin_url": url}

                    batch.append(("GET", fullUrl, {"headers": self.headers,
                                                "allow_redirects": self.cfg["http"]["redirects"]["submit"]}, meta))

        if not batch:
            return []

        findings = self.runBatch(batch, concurrency=self.cfg["concurrency"]["max_workers"])

        return findings

    def analyzeResponse(self, response, meta):
        """
            analyze the response for stored XSS
        """

        target = response.url
        loc = response.headers.get("Location")
        if 300 <= response.status_code < 400 and loc:
            target = urljoin(response.url, loc)

        # revisit without payload to check if stored
        revisit = (meta or {}).get("origin_url") or target
        revisit = revisit.split("?", 1)[0]
        try:
            res = self.session.get(revisit, headers=self.headers, timeout=self.cfg["http"]["timeout_get_seconds"], allow_redirects=True)
        except Exception:
            log.debug("Revisit check failed for %s", revisit, exc_info=True)
            return None

        # Skip non-HTML, xml and javascript
        ctype = (res.headers.get("Content-Type") or "").lower()

        if ctype and all(t not in ctype for t in ("html", "xml", "javascript", "svg")):
            return None

        revisitB = res.content or b""
        if self.tokenB not in revisitB:
            return None

        enc = res.encoding or "utf-8"
        body = revisitB.decode(enc, errors="ignore")
        low = body.lower()
        lowU = unescape(body).lower()
        lowQ = unquote_plus(body).lower()

        marked = (meta or {}).get("marked")
        if marked:
            mlow = marked.lower()
            if mlow not in low and mlow not in lowU and mlow not in lowQ:
                return None

        ok, indicator = self.ctx.dete.detect_xss(body, self.token)

        if not ok:
            return None

        payload = (meta or {}).get("payload")
        method = (meta or {}).get("method")
        finding = Finding(
            type="xss_stored",
            url=res.url,
            method=method,
            payload=payload,
            indicator=(indicator or "N/A"),
            status_code=res.status_code,
            response_snippet=body[:200],
        )
        setattr(finding, "bail", True)
        return finding