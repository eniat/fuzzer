import logging

from urllib.parse import urlparse, quote

from ..runtime.context import AppContext
from ..core.base_fuzzer import AbstractFuzzer
from ..core.reporting import Finding

log = logging.getLogger(__name__)

class BlindSQLiFuzzer(AbstractFuzzer):
    """
        Takes the forms retrieved by the crawler and fuzzes them for SQLi blind vulnerabilities
    """

    def __init__(self, baseUrl, wordlistPath=None, session=None, bailEvent=None, cfg=None, auth=False, loginUsername=None, loginPassword=None, loginPath=None, headers=None, ctx: AppContext | None = None):
        super().__init__(baseUrl=baseUrl, session=session, headers=headers, wordlistPath=wordlistPath, bailEvent=bailEvent, cfg=cfg)
        self.ctx=ctx
        if self.ctx is None:
            raise ValueError("Sqli Blind Fuzzer requires an AppContext")

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
        # Build boolean true/False pairs
        self.boolPairs = self.ctx.util.build_boolean_payloads()

        # Sort to make sure no duplicates
        self.boolPairs = list(dict.fromkeys(self.boolPairs))
        self.payloads = list(dict.fromkeys(self.payloads))

        self.MAX_SAMPLES_PER_GROUP = self.cfg["sqli"]["max_samples_per_group"]
        self.TIMING_PAYLOAD_TRIALS = self.cfg["sqli"]["timing_payload_trials"]
        self.TIMING_CONFIRM_PROBES = self.cfg["sqli"]["timing_confirm_probes"]

        self.targets = []
        self.precheckBools = {}
        self.vulnerableForms = {}


    def prepare(self, ctx):
        """
            Get valid form/targets probe and make payloads
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

        # Forms first
        for form in forms:

            url = form.get("url")
            method = (form.get("method") or "POST").upper()
            fields = form.get("formFields") or []

            # Skip invalid form objects
            if not url or not fields:
                continue

            if not url.startswith("http"):
                url = f"{origin}{url}"

            fuzzTargets = [f for f in fields if self.ctx.util.is_fuzzable_field(f)]
            if not fuzzTargets:
                continue

            tkey = (url, method, tuple(sorted(fields)))
            if tkey in seen:
                continue
            seen.add(tkey)

            # Get a baseline for later comparisons
            baseText, baseStatus = self.ctx.base.sqli_baseline(self.session, url, method, fields, util=self.ctx.util, headers=self.headers)

            self.targets.append({
                "url": url,
                "method": method,
                "fields": fields,
                "fuzz_targets": fuzzTargets,
                "base_text": baseText,
                "base_status": baseStatus,
            })


    def run(self, ctx=None):
        """
            Build batch and execute via runBatch
        """
        self.prepare(ctx)
        bSeen = set()

        if not self.targets:
            return []

        # First create the boolean batch
        boolBatch = []
        for targ in self.targets:
            # If bail on first then bail
            if self.bailEvent and self.bailEvent.is_set():
                break

            url, method, fields = targ["url"], targ["method"], targ["fields"]
            baseText = targ["base_text"]

            for trueCond, falseCond in self.boolPairs:
                # If bail on first then bail
                if self.bailEvent and self.bailEvent.is_set():
                    break

                pairId = f"{trueCond}|||{falseCond}"
                fKey = tuple(sorted(fields))
                bKeyT = ("BOOL", method, url, fKey, pairId, "T")
                bKeyF = ("BOOL", method, url, fKey, pairId, "F")

                doTrue = bKeyT not in bSeen
                doFalse = bKeyF not in bSeen
                if doTrue:bSeen.add(bKeyT)
                if doFalse: bSeen.add(bKeyF)

                if method == "POST":
                    # POST form fuzzing
                    dataTrue = {}
                    dataFalse = {}

                    for field in fields:
                        # Inject into fuzzable fields the 1 plus a true condition and a false condition
                        if self.ctx.util.is_fuzzable_field(field):
                            dataTrue[field] = "1" + trueCond
                            dataFalse[field] = "1" + falseCond

                        else:
                            dataTrue[field] = "1"
                            dataFalse[field] = "1"

                    dataTrue = self.ctx.util.auto_submits(baseText, dataTrue)
                    dataFalse = self.ctx.util.auto_submits(baseText, dataFalse)
                    if doTrue:
                        boolBatch.append((
                            "POST", url, {"headers": self.headers, "data": dataTrue,
                             "timeout": self.cfg["sqli"]["timeout_blind"], "allow_redirects": self.cfg["http"]["redirects"]["fuzz_post"]},
                            {"phase": "bool", "kind": "bool_true", "pair_id": pairId, "method": "POST",
                             "url": url, "raw_url": url, "fields": tuple(sorted(fields)), "cond": trueCond}
                        ))
                    if doFalse:
                        boolBatch.append((
                            "POST", url, {"headers": self.headers, "data": dataFalse,
                             "timeout": self.cfg["sqli"]["timeout_blind"], "allow_redirects": self.cfg["http"]["redirects"]["fuzz_post"]},
                            {"phase": "bool", "kind": "bool_false", "pair_id": pairId, "method": "POST",
                             "url": url, "raw_url": url, "fields": tuple(sorted(fields)), "cond": falseCond}
                        ))

                else:
                    # GET form fuzzing
                    paramsTrue = {}
                    paramsFalse = {}

                    for field in fields:
                        # Inject into fuzzable fields the 1 plus a true condition and a false condition
                        if self.ctx.util.is_fuzzable_field(field):
                            paramsTrue[field] = "1" + trueCond
                            paramsFalse[field] = "1" + falseCond

                        else:
                            paramsTrue[field] = "1"
                            paramsFalse[field] = "1"

                    paramsTrue = self.ctx.util.auto_submits(baseText, paramsTrue)
                    paramsFalse = self.ctx.util.auto_submits(baseText, paramsFalse)

                    # Contruct GET requests
                    logParamsT = [f"{k}={quote(str(v), safe='')}" for k, v in paramsTrue.items()]
                    logParamsF = [f"{k}={quote(str(v), safe='')}" for k, v in paramsFalse.items()]

                    separator = "&" if "?" in url else "?"

                    fullUrlT = f"{url}{separator}{'&'.join(logParamsT)}"
                    fullUrlF = f"{url}{separator}{'&'.join(logParamsF)}"

                    if doTrue:
                        boolBatch.append((
                            "GET", url, {"headers": self.headers, "params": paramsTrue,
                             "timeout": self.cfg["sqli"]["timeout_blind"], "allow_redirects": self.cfg["http"]["redirects"]["fuzz_get"]},
                            {"phase": "bool", "kind": "bool_true", "pair_id": pairId, "method": "GET",
                             "url": fullUrlT, "raw_url": url, "fields": tuple(sorted(fields)), "cond": trueCond}
                        ))
                    if doFalse:
                        boolBatch.append((
                            "GET", url,{"headers": self.headers, "params": paramsFalse,
                             "timeout": self.cfg["sqli"]["timeout_blind"], "allow_redirects": self.cfg["http"]["redirects"]["fuzz_get"]},
                            {"phase": "bool", "kind": "bool_false", "pair_id": pairId, "method": "GET",
                             "url": fullUrlF, "raw_url": url, "fields": tuple(sorted(fields)), "cond": falseCond}
                        ))

        boolFindings = self.runBatch(boolBatch, concurrency=self.cfg["concurrency"]["max_workers"])

        # If bail on first then bail
        if self.bailEvent and self.bailEvent.is_set():
            return boolFindings

        # If there are no potential timing payloads skip
        if not self.payloads or not any(self.ctx.util.is_blind_payload(payload) for payload in self.payloads):
            return boolFindings

        # Sequentially fuzz for blind timing
        timingFindings = []
        blSeen = set()
        for targ in self.targets:
            # If bail on first then bail
            if self.bailEvent and self.bailEvent.is_set():
                break

            url, method, fields = targ["url"], targ["method"], targ["fields"]
            baseText = targ["base_text"]

            baselineMs = self.ctx.base.get_blind_baseline(self.session, url, method, fields, util=self.ctx.util, probes = self.cfg["sqli"]["timing_baseline_probes"] ,headers=self.headers)

            if baselineMs <= 0.0:
                continue

            confirmJobs = []
            for raw in self.payloads:
                # If bail on first then bail
                if self.bailEvent and self.bailEvent.is_set():
                    break

                if not self.ctx.util.is_blind_payload(raw):
                    continue

                payload = self.ctx.util.expand_time_token(raw)
                targets = [f for f in fields if self.ctx.util.is_fuzzable_field(f)]
                if not targets:
                    continue

                for target in targets:
                    # If bail on first then bail
                    if self.bailEvent and self.bailEvent.is_set():
                        break
                    data = {}
                    params = {}

                    if method == "POST":
                        # POST form fuzzing
                        data = {f: (payload if f == target else "1") for f in fields}
                        data = self.ctx.util.auto_submits(baseText, data)

                    else:
                        # GET form fuzzing
                        params = {f: (payload if f == target else "1") for f in fields}
                        params = self.ctx.util.auto_submits(baseText, params)

                    # Run multiple trials to get more accurate reading
                    trialElapses = []

                    for _ in range(max(1, int(self.TIMING_PAYLOAD_TRIALS))):
                        try:
                            if method == "POST":
                                res = self.session.post(url, data=data, headers=self.headers,
                                                        timeout=self.cfg["sqli"]["timeout_blind"],
                                                        allow_redirects=self.cfg["http"]["redirects"]["fuzz_post"])

                            else:
                                res = self.session.get(url, params=params, headers=self.headers,
                                                       timeout=self.cfg["sqli"]["timeout_blind"],
                                                       allow_redirects=self.cfg["http"]["redirects"]["fuzz_get"])

                            # Convert and keep only time data
                            trialElapses.append(res.elapsed.total_seconds() * 1000.0)

                        except Exception:
                            log.debug("Timing trial request failed for %s", url, exc_info=True)
                            continue

                    if not trialElapses:
                        continue

                    # Use the median to help with anomalies
                    trialElapses.sort()
                    mid = len(trialElapses) // 2
                    testMs = trialElapses[mid] if len(trialElapses) % 2 == 1 else (trialElapses[mid - 1] + trialElapses[mid]) / 2.0

                    if not self.ctx.dete.detect_sqli_blind(baselineMs, testMs):
                        continue

                    ckey = (url, method, tuple(sorted(fields)), target, payload)
                    if ckey in blSeen:
                        continue
                    blSeen.add(ckey)
                    confirmJobs.append((target, payload))

            # Check previous hits again serially to stop other payloads having a domino effect
            if confirmJobs:
                    confirmBaseMs = self.ctx.base.get_blind_baseline(self.session, url, method, fields, probes=self.TIMING_CONFIRM_PROBES, util=self.ctx.util, headers = self.headers) or baselineMs
                    for (target, payload) in confirmJobs:
                        try:
                            if method == "POST":
                                # POST form fuzzing
                                data = {f: (payload if f == target else "1") for f in fields}
                                data = self.ctx.util.auto_submits(baseText, data)

                                res = self.session.post(
                                    url,
                                    data=data,
                                    headers=self.headers,
                                    timeout=self.cfg["sqli"]["timeout_blind"],
                                    allow_redirects=self.cfg["http"]["redirects"]["fuzz_post"]
                                )

                            else:
                                # GET form fuzzing
                                params = {f: (payload if f == target else "1") for f in fields}
                                params = self.ctx.util.auto_submits(baseText, params)

                                res = self.session.get(
                                    url,
                                    params=params,
                                    headers=self.headers,
                                    timeout=self.cfg["sqli"]["timeout_blind"],
                                    allow_redirects=self.cfg["http"]["redirects"]["fuzz_get"]
                                )

                        except Exception:
                            log.debug("Timing confirm request failed for %s", url, exc_info=True)
                            continue

                        # Confirm the timing
                        testMs = res.elapsed.total_seconds() * 1000.0
                        if not self.ctx.dete.detect_sqli_blind(confirmBaseMs, testMs):
                            continue

                        # Record the confirmed payload
                        finUrl = getattr(res, "url", url) or url
                        pageKey = finUrl.split("?", 1)[0].split("#", 1)[0]
                        resultsKey = (pageKey, "blind_sql_timing", "sqli_blind")

                        find = self.vulnerableForms.get(resultsKey)
                        if not find:
                            self.vulnerableForms[resultsKey] = Finding(
                                type="sqli_blind",
                                url=pageKey,
                                method=method,
                                param=None,
                                payload=payload,
                                indicator="blind_sql_timing",
                                status_code=res.status_code,
                                count=1,
                                payload_samples=[payload],
                                response_snippet=(res.text or "")[:200]
                            )
                            find = self.vulnerableForms[resultsKey]

                        else:
                            find.count = (find.count or 0) + 1
                            if len(find.payload_samples) < self.MAX_SAMPLES_PER_GROUP and payload not in find.payload_samples:
                                find.payload_samples.append(payload)

                        setattr(find, "bail", True)
                        timingFindings.append(find)

        return (boolFindings or []) + (timingFindings or [])


    def analyzeResponse(self, response, meta):
        """
            analyze the response for successful SQL blind injection
        """
        meta = meta or {}
        if meta.get("phase") != "bool":
            return None

        kind = meta.get("kind")
        method = meta.get("method")
        pairId = meta.get("pair_id")
        fields = meta.get("fields") or ()
        rawUrl = meta.get("raw_url") or meta.get("url") or getattr(response, "url", "")
        finUrl = getattr(response, "url", meta.get("url") or "")
        body = response.text or ""
        statusC = getattr(response, "status_code", 0)
        condStr = meta.get("cond", "")

        # Store bools then check when we have both
        key = (method, rawUrl, fields, pairId)
        slot = self.precheckBools.setdefault(key, {})
        slot[kind] = {"body": body, "status": statusC, "url": finUrl, "cond": condStr}

        if "bool_true" not in slot or "bool_false" not in slot:
            return None

        true, false = slot["bool_true"], slot["bool_false"]

        if self.ctx.dete.detect_sqli_diff(true["body"], false["body"], is_not_sqli_blind=False, true=true["cond"], false=false["cond"]):

            # Check for slight absolute length change for less false positives
            sizeDelta = abs(len(true["body"]) - len(false["body"]))
            if true["status"] != false["status"] or sizeDelta >= 1:

                pageKey = (true["url"] or finUrl).split("?", 1)[0].split("#", 1)[0]
                resultsKey = (pageKey, "blind_sql_boolean", "sqli_blind")
                payloadUsed = f'TRUE:{true["cond"]} | FALSE:{false["cond"]}'

                find = self.vulnerableForms.get(resultsKey)
                if not find:
                    self.vulnerableForms[resultsKey] = Finding(
                        type="sqli_blind",
                        url=pageKey,
                        method=method,
                        param=None,
                        payload=payloadUsed,
                        indicator="blind_sql_boolean",
                        status_code=true["status"],
                        count=1,
                        payload_samples=[payloadUsed],
                        response_snippet=(true["body"] or "")[:200],
                    )
                    find = self.vulnerableForms[resultsKey]

                else:
                    find = self.vulnerableForms[resultsKey]
                    find.count = (find.count or 0) + 1
                    if len(find.payload_samples) < self.MAX_SAMPLES_PER_GROUP and payloadUsed not in find.payload_samples:
                        find.payload_samples.append(payloadUsed)
                setattr(find, "bail", True)
                self.precheckBools.pop(key, None)
                return find

            self.precheckBools.pop(key, None)
            return None