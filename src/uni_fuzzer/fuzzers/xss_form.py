import logging
from html import unescape

from urllib.parse import urlparse, quote, unquote_plus
from uuid import uuid4

from uni_fuzzer.core.base_fuzzer import AbstractFuzzer
from uni_fuzzer.core.reporting import Finding
from uni_fuzzer.core.probes import probeReflexivity
from uni_fuzzer.auth.auth import login
from uni_fuzzer.core.baseline import baselineForm

from uni_fuzzer.core.utility import isFuzzableField, loadWordlist, autoSubmits, canary, status
from uni_fuzzer.fuzzers.detection import detectXSS

log = logging.getLogger(__name__)

class FormXSSFuzzer(AbstractFuzzer):
    """
        Takes the forms retrieved by the crawler and fuzzes them for reflected XSS
    """

    def __init__(self, baseUrl, wordlistPath=None, session=None, bailEvent=None, cfg=None, auth=False, loginUsername=None, loginPassword=None, loginPath=None, token=None, headers=None):
        super().__init__(baseUrl=baseUrl, session=session, headers=headers, wordlistPath=wordlistPath, bailEvent=bailEvent, cfg=cfg)

        if self.cfg["http"]["add_referer"]:
            self.headers["Referer"] = self.baseUrl

        self.payloads = loadWordlist(self.wordlistPath) if self.wordlistPath is not None else []
        self.token = token or f"XSSCanary-{uuid4().hex[:8]}"
        self.tokenLow = self.token.lower()
        self.tokenB = self.token.encode("utf-8", errors="ignore")

        self.auth = auth
        self.loginUsername = loginUsername
        self.loginPassword = loginPassword
        self.loginPath = loginPath

        self.prepared = False
        self.prebuiltPayloads = []

        if self.auth:
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

        if isinstance(ctx, dict):
            forms = ctx.get("forms")
        else:
            forms = getattr(ctx, "forms", None)

        if not self.prepared:
            self.prepare(None)

        if not forms:
            # If not reflective no need to fuzz
            return []

        batch = []

        for form in (forms or []):
            # If bail on first then bail
            if self.bailEvent and self.bailEvent.is_set():
                break

            url = form.get("url")
            method = (form.get("method") or "POST").upper()
            fields = form.get("formFields") or []

            # Skip invalid form objects
            if not url or not fields:
                log.debug("Skipping invalid form object (url/fields missing): %s", form)
                continue

            # Normalize Url
            parsed = urlparse(self.baseUrl)
            if not url.startswith("http"):
                url = f"{parsed.scheme}://{parsed.netloc}{url}"

            fuzzField = [f for f in fields if isFuzzableField(f)]

            if not fuzzField:
                log.debug("No fuzzable fields for form %s", url)
                continue

            # Singular probe to check if reflective
            try:
                if not probeReflexivity(self.session, url, method, fields, fuzzField, self.headers, self.token):
                    log.debug("Form not reflective %s", url)
                    continue

            except Exception:
                log.debug("probeReflexivity failed for %s", url, exc_info=True)
                continue

            # Get baseline to check for submit buttons
            try:
                base = baselineForm(self.session, url, self.headers)
                baseHtml = base.get("content") or ""
            except Exception:
                log.debug("baselineForm failed for %s", url, exc_info=True)
                baseHtml = ""

            if method == "POST":
                # POST form fuzzing
                baseD = {f: "test" for f in fields}
                baseD = autoSubmits(baseHtml, baseD)
                for raw, marked, _enc in self.prebuiltPayloads:
                    # If bail on first then bail
                    if self.bailEvent and self.bailEvent.is_set():
                        break
                    data = dict(baseD)
                    for f in fuzzField:
                        data[f] = marked

                    meta = {
                        "kind": "xss_form",
                        "payload": raw,
                        "marked": marked,
                        "method": "POST",
                        "phase": "submit"
                    }

                    batch.append(("POST", url, {"headers": self.headers, "data": data, "allow_redirects": False},meta))

            else:
                # GET form fuzzing
                baseP = {f: "test" for f in fields}
                separator = "&" if "?" in url else "?"

                for raw, marked, enc in self.prebuiltPayloads:
                    # If bail on first then bail
                    if self.bailEvent and self.bailEvent.is_set():
                        break
                    params = dict(baseP)
                    for f in fuzzField:
                        params[f] = enc

                    logParams = [f"{k}={quote(str(v), safe='')}" for k, v in params.items()]
                    fullUrl = f"{url}{separator}{'&'.join(logParams)}"

                    meta = {
                        "kind": "xss_form",
                        "payload": raw,
                        "marked": marked,
                        "method": "GET",
                        "phase": "submit"
                    }

                    batch.append(( "GET", fullUrl,{"headers": self.headers, "allow_redirects": False}, meta))

        if not batch:
            return []

        findings = self.runBatch(batch, concurrency=self.cfg["concurrency"]["max_workers"])

        return findings


    def analyzeResponse(self, response, meta):
        """
            analyze the response for reflected XSS
        """
        # Skip non-HTML, xml and javascript
        ctype = (response.headers.get("Content-Type") or "").lower()

        if ctype and ("html" not in ctype and "xml" not in ctype and "javascript" not in ctype):
            return None

        # If token bytes not present skip
        content = response.content or b""
        if self.tokenB not in content:
            return None

        enc = response.encoding or "utf-8"
        body = content.decode(enc, errors="ignore")
        low = body.lower()

        # Detect XSS with detect function
        marked = (meta or {}).get("marked")
        if marked:
            mlow = marked.lower()
            if (mlow not in low
                    and unescape(body).lower().find(mlow) == -1
                    and unquote_plus(body).lower().find(mlow) == -1):
                return None

        ok, indicator = detectXSS(body, self.token, marked)

        if not ok:
            return None

        payload = (meta or {}).get("payload")
        method = (meta or {}).get("method")
        return Finding(
            type="xss_form",
            url=response.url,
            method=method,
            payload=payload,
            indicator=(indicator or "N/A"),
            status_code=response.status_code,
            response_snippet=body[:200],
        )
