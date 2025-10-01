import time
import logging

from urllib.parse import urljoin, urlparse, quote, unquote_plus
from uuid import uuid4
from html import unescape

from uni_fuzzer.core.base_fuzzer import AbstractFuzzer
from uni_fuzzer.core.reporting import Finding
from uni_fuzzer.auth.auth import  login
from uni_fuzzer.core.baseline import baselineForm
from uni_fuzzer.fuzzers.detection import detectXSS

from uni_fuzzer.core.utility import  isFuzzableField, loadWordlist, autoSubmits, canary, status

log = logging.getLogger(__name__)

class StoredXSSFuzzer(AbstractFuzzer):
    """
        Submits payload then revisits to see if payload still there
    """

    def __init__(self, baseUrl, wordlistPath=None, session=None, bailEvent=None, cfg=None, auth=False, loginUsername=None, loginPassword=None, loginPath=None, token=None, headers=None):
        super().__init__(baseUrl=baseUrl, session=session, headers=headers, wordlistPath=wordlistPath, bailEvent=bailEvent, cfg=cfg)

        if self.cfg["http"]["add_referer"]:
            self.headers["Referer"] = self.baseUrl

        self.payloads = loadWordlist(self.wordlistPath) if self.wordlistPath is not None else []
        self.token = token or f"XSSCanary-{uuid4().hex[:8]}"
        self.tokenLow = self.token.lower()

        self.auth = auth
        self.loginUsername = loginUsername
        self.loginPassword = loginPassword
        self.loginPath = loginPath

        self.prepared = False
        self.prebuiltPayloads = []
        self.reported = set()

        if self.auth and self.loginUsername and self.loginPassword:
            # Use the generic HTTP login in auth.py
            ok = login(
                self.session,
                baseUrl=self.baseUrl,
                username=self.loginUsername,
                password=self.loginPassword,
                loginPath=self.loginPath,
                selectors=None,
                headers=None
            )
            if not ok:
                status("[!] HTTP login in XSSFuzzer failed")
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
            marked = canary(raw, self.token)
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
            endpoints = ctx.get("endpoints")
        else:
            forms = getattr(ctx, "forms", None)
            endpoints = getattr(ctx, "endpoints", None)

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

            fuzzFields = [f for f in fields if isFuzzableField(f)]

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
                baseD = autoSubmits(baseHtml, baseD)
                for raw, marked, enc in self.prebuiltPayloads:
                    # If bail on first then bail
                    if self.bailEvent and self.bailEvent.is_set():
                        break
                    data = dict(baseD)
                    for f in fuzzFields:
                        data[f] = marked

                    meta = {"phase": "submit", "kind": "xss_stored_submit",
                            "payload": raw, "marked": marked,
                            "submit_method": "POST", "orig_url": url}

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
                            "submit_method": "GET", "orig_url": url}

                    batch.append(("GET", fullUrl, {"headers": self.headers,
                                                "allow_redirects": self.cfg["http"]["redirects"]["submit"]}, meta))


        # Collect results
        if batch:
            for res, meta in self.runBatch(batch, concurrency=self.cfg["concurrency"]["max_workers"],collectRaw=True):

                try:
                    if hasattr(res, "url"):
                        finUrl = getattr(res, "url", None)

                        if finUrl and finUrl not in pages:
                            pages.append(finUrl)
                        loc = res.headers.get("Location")

                        if loc:
                            dest = loc if loc.startswith("http") else urljoin(finUrl or origin, loc)
                            if dest and dest not in pages:
                                pages.append(dest)

                except Exception:
                    log.debug("Submission post process failed", exc_info=True)

        #Merge extra endpoints
        if endpoints:
            for end in endpoints:
                if not end:
                    continue

                if isinstance(end, str):
                    dest = end if end.startswith("http") else f"{origin}{end}"

                else:
                    rawUrl = end.get("url")
                    dest = rawUrl if (rawUrl and rawUrl.startswith("http")) else (f"{origin}{rawUrl}" if rawUrl else None)
                if dest and dest not in pages:
                    pages.append(dest)
        if not pages:
            return []

        # Short wait for settle
        try:
            time.sleep(self.cfg["xss"]["stored_settle_seconds"])
        except Exception:
            log.debug("Sleep interrupted during stored settle", exc_info=True)

        # Revisit part

        revisitHeaders = dict(self.headers)
        revisitHeaders["Cache-Control"] = "no-cache"
        revisitHeaders["Pragma"] = "no-cache"
        revisitHeaders["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

        pages = list(dict.fromkeys(pages))
        batchR = []
        for page in pages:
            meta = {
                "phase": "revisit",
                "kind": "xss_stored_revisit"
            }
            batchR.append(("GET", page,{"headers": revisitHeaders,
                                   "allow_redirects": self.cfg["http"]["redirects"]["stored_xss"]}, meta))

        if not batchR:
            return []

        findings = self.runBatch(batchR, concurrency=self.cfg["concurrency"]["max_workers"])
        return findings


    def analyzeResponse(self, response, meta):
        """
            analyze the response for stored XSS
        """

        if (meta or {}).get("phase") != "revisit":
            return None

        ctype = (response.headers.get("Content-Type") or "").lower()
        if ctype and all(t not in ctype for t in ("html", "xml", "javascript", "svg")):
            return None

        body = response.text or ""
        low = body.lower()
        lowU = unescape(body).lower()
        lowQ = unquote_plus(body).lower()

        # If no token quick detect pass
        if self.tokenLow not in low and self.tokenLow not in lowU and self.tokenLow not in lowQ:
            return None

        finUrl = getattr(response, "url", "") or ""
        base = finUrl.split("?", 1)[0].split("#", 1)[0]

        # Check if payloads still persists
        try:
            p = urlparse(base)
            scheme = (p.scheme or "").lower()
            netloc = (p.netloc or "").lower()
            path = p.path or "/"

            if path != "/" and path.endswith("/"):
                path = path.rstrip("/")
            pageKey = f"{scheme}://{netloc}{path}"

        except Exception:
            pageKey = (base.rstrip("/")).lower()

        ok, indicator = detectXSS(body, self.token)
        if not ok:
            return None
        indicator = indicator or "N/A"

        chosen = None
        for rawSamp, markedSamp, _ in self.prebuiltPayloads:
            mlow = markedSamp.lower()
            if mlow in low or mlow in lowU or mlow in lowQ:
                chosen = (rawSamp, markedSamp)
                break

        if chosen is None:
            rawRep, markedRep = (None, self.token)
        else:
            rawRep, markedRep = chosen

        # Check if reported before
        key = (pageKey, (indicator or "N/A"), markedRep)
        if key in self.reported:
            return None
        self.reported.add(key)
        finding =  Finding(
            type="xss_stored",
            url=pageKey,
            method="GET",
            payload=rawRep,
            indicator=(indicator or "N/A"),
            status_code=response.status_code,
            response_snippet=body[:200]
        )
        setattr(finding, "bail", True)
        return finding