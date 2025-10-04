import logging

from urllib.parse import urlparse, quote

from ..core.probes import probeReactivity
from ..fuzzers.detection import detectSQLiDiff, detectSQLError
from ..core.baseline import sqliBaseline

from uni_fuzzer.runtime.context import AppContext
from ..core.base_fuzzer import AbstractFuzzer
from ..core.reporting import Finding

log = logging.getLogger(__name__)

class InjSQLFuzzer(AbstractFuzzer):
    """
        Takes the forms retrieved by the crawler and fuzzes them for SQLi vulnerabilities
    """

    def __init__(self, baseUrl, wordlistPath=None, session=None, bailEvent=None, cfg=None, auth=False,loginUsername=None, loginPassword=None, loginPath=None,headers=None, ctx: AppContext | None = None):
        super().__init__(baseUrl=baseUrl, session=session, headers=headers, wordlistPath=wordlistPath,bailEvent=bailEvent, cfg=cfg)
        self.ctx=ctx
        if self.ctx is None:
            raise ValueError("Sqli Fuzzer requires an AppContext")

        if self.cfg["http"]["add_referer"]:
            self.headers["Referer"] = self.baseUrl

        # Authentication
        self.loginUsername = loginUsername
        self.loginPassword = loginPassword
        self.loginPath = loginPath
        self.auth = auth
        if self.auth and self.loginUsername and self.loginPassword:
            ok = self.ctx.auth.http_login(self.session, self.baseUrl, self.loginUsername, self.loginPassword, self.loginPath)
            if not ok:
                self.ctx.util.status("[!] HTTP login in SQLi Fuzzer failed")
                log.warning("HTTP login in SQLi Fuzzer failed")

        self.payloads = self.ctx.util.load_wordlist(self.wordlistPath) if self.wordlistPath is not None else []

        self.MAX_SAMPLES_PER_GROUP = self.cfg["sqli"]["max_samples_per_group"]

        self.targets = []
        self.vulnerableForms = {}


    def prepare(self, ctx):
        """
            Get valid form/target and probe
        """
        self.targets = []
        seen = set()
        if not ctx:
            return

        if isinstance(ctx, dict):
            forms = ctx.get("forms") or []
        else:
            forms = getattr(ctx, "forms", []) or []

        # Normalize Urls
        parsed = urlparse(self.baseUrl)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Sort Forms first for valid targets
        for form in forms:

            url = form.get("url")
            method = (form.get("method") or "POST").upper()
            fields = form.get("formFields") or []

            # Skip invalid form objects
            if not url or not fields:
                continue

            if not url.startswith("http"):
                url = f"{origin}{url}"

            tkey = (url, method, tuple(sorted(fields)))
            if tkey in seen:
                continue
            seen.add(tkey)

            fuzzTargets = [f for f in fields if self.ctx.util.is_fuzzable_field(f)]
            if not fuzzTargets:
                continue

            if not probeReactivity(self.session, url, method, fields, fuzzTargets, self.headers):
                continue

            # Get a baseline for later comparisons
            baseText, baseStatus = sqliBaseline(self.session, self.headers, url, method, fields, util=self.ctx.util)

            self.targets.append({
                "url": url,
                "method": method,
                "fields": fields,
                "fuzz_targets": fuzzTargets,
                "base_text": baseText,
                "base_status": baseStatus
            })
        log.info("[SQLi] prepared %d forms (reactive & fuzzable)", len(self.targets))


    def run(self, ctx=None):
        """
            Build batch and execute via runBatch
        """
        self.prepare(ctx)

        findings = []
        seen = set()

        if not self.targets or not self.payloads:
            log.info("[SQLi] nothing to fuzz ")
            return list(self.vulnerableForms.values())

        for targ in self.targets:
            url, method, fields = targ["url"], targ["method"], targ["fields"]
            fuzzTargets = targ["fuzz_targets"]
            baseText, baseStatus = targ["base_text"], targ["base_status"]

            batch = []

            planned = len(self.payloads) * len(fuzzTargets)
            log.info("[SQLi] planning %d requests for %s %s", planned, method, url)

            for raw in self.payloads:
                # If bail on first then bail
                if self.bailEvent and self.bailEvent.is_set():
                    break

                jKey = (method, url, tuple(sorted(fields)), raw)
                if jKey in seen:
                    continue
                seen.add(jKey)

                for target in fuzzTargets:
                    # If bail on first then bail
                    if self.bailEvent and self.bailEvent.is_set():
                        break

                    if method == "POST":
                        # POST form fuzzing
                        data = {f: (raw if f == target else "1") for f in fields}
                        data = self.ctx.util.auto_submits(baseText, data)
                        meta = {
                            "url": url, "method": "POST", "target": target, "payload": raw,
                            "base_text": baseText, "base_status": baseStatus, "fields": fields,"origin_url": url
                        }
                        batch.append((
                            "POST", url,{"data": data, "headers": self.headers,
                             "timeout": self.cfg["http"]["timeout_post_seconds"],
                             "allow_redirects": self.cfg["http"]["redirects"]["fuzz_post"]},meta))

                    else:
                        # GET form fuzzing
                        params = {f: (raw if f == target else "1") for f in fields}
                        params = self.ctx.util.auto_submits(baseText, params)

                        # Contruct GET requests
                        logParams = [f"{k}={quote(str(v), safe='')}" for k, v in params.items()]
                        separator = "&" if "?" in url else "?"
                        fullUrl = f"{url}{separator}{'&'.join(logParams)}"

                        meta = {
                            "url": fullUrl, "method": "GET", "target": target, "payload": raw,
                            "base_text": baseText, "base_status": baseStatus, "fields": fields,"origin_url": url
                        }

                        batch.append((
                            "GET", url,{"params": params, "headers": self.headers,
                             "timeout": self.cfg["http"]["timeout_get_seconds"],
                            "allow_redirects": self.cfg["http"]["redirects"]["fuzz_get"]}, meta
                        ))

            findings = self.runBatch(batch, concurrency=self.cfg["concurrency"]["max_workers"])
        return findings or list(self.vulnerableForms.values())


    def analyzeResponse(self, response, meta):
        """
            analyze the response for successful SQL injection or SQL errors
        """
        body = (response.text or "")
        statusC = getattr(response, "status_code", 0)

        baseText = (meta or {}).get("base_text", "")
        baseStatus = (meta or {}).get("base_status", 0)
        payload = (meta or {}).get("payload")
        method = (meta or {}).get("method")
        target = (meta or {}).get("target")
        finUrl = (meta or {}).get("url") or getattr(response, "url", "")

        fields = meta.get("fields") or []
        actionUrl = meta.get("origin_url") or finUrl.split("?", 1)[0]

        # Fresh baseline to double check
        freshText, freshStatus = sqliBaseline(self.session, self.headers, actionUrl, method, fields, util=self.ctx.util)

        # Check for SQL Error
        isErr, indicator = detectSQLError(body)

        if isErr or (statusC != baseStatus and statusC >= 400):

            fErr, _ = detectSQLError(freshText or "")
            if fErr or (freshStatus != baseStatus and freshStatus >= 400):
                log.debug("Second baseline matched (%s) false positive", actionUrl)
                return None

            pageKey = finUrl.split("?", 1)[0].split("#", 1)[0]
            resultsKey = (pageKey,"sql_error", "sqli_potential")
            find = self.vulnerableForms.get(resultsKey)
            if not find:
                self.vulnerableForms[resultsKey] = Finding(
                    type="sqli_potential",
                    url=pageKey,
                    method=method,
                    param=target,
                    payload=payload,
                    indicator=indicator or "sql_error",
                    status_code=statusC,
                    count=1,
                    payload_samples=[payload] if payload is not None else [],
                    response_snippet=(body or "")[:200]
                )
                find = self.vulnerableForms[resultsKey]

            else:
                if payload is not None and len(find.payload_samples) < self.MAX_SAMPLES_PER_GROUP and payload not in find.payload_samples:
                    find.payload_samples.append(payload)
                    find.count = (find.count or 0) + 1
            setattr(find, "bail", False)
            return find

        # Check for valid SQLi ran code
        freshTrips = (freshStatus != baseStatus) or detectSQLiDiff(baseText, freshText or "", payload=None)
        if baseStatus and (statusC != baseStatus or detectSQLiDiff(baseText, body, payload=payload)):
            if freshTrips:
                log.debug("Second baseline matched (%s) false positive", actionUrl)
                return None

            pageKey = finUrl.split("?", 1)[0].split("#", 1)[0]
            resultsKey = (pageKey, method, target, "detected_sql_content", "sqli_inj")
            find = self.vulnerableForms.get(resultsKey)

            if not find:
                self.vulnerableForms[resultsKey] = Finding(
                    type="sqli_inj",
                    url=pageKey,
                    method=method,
                    param=target,
                    payload=payload,
                    indicator="detected_sql_content",
                    status_code=statusC,
                    count=1,
                    payload_samples=[payload] if payload is not None else [],
                    response_snippet=(body or "")[:200]
                )
                find = self.vulnerableForms[resultsKey]
                setattr(find, "bail", True)
            else:
                if payload is not None and len(find.payload_samples) < self.MAX_SAMPLES_PER_GROUP and payload not in find.payload_samples:
                    find.payload_samples.append(payload)
                    find.count = (find.count or 0) + 1
            return find

        return None