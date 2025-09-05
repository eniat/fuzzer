import requests
import threading
import re
from urllib.parse import urlparse, quote, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter

from uni_fuzzer.auth.auth import login

from uni_fuzzer.core.utility import get_cfg, isFuzzableField, loadWordlist
cfg = get_cfg()

SQL = cfg["sqli"]["error_signatures"]
MAX_SAMPLES_PER_GROUP = cfg["sqli"]["max_samples_per_group"]

TIMING_THRESHOLD_MS = cfg["sqli"]["timing_threshold_ms"]
BLIND_MARKERS = cfg["sqli"]["blind_markers"]
BLIND_FACTOR  = cfg["sqli"]["blind_timing_factor"]
BLIND_TIME = cfg["sqli"]["blind_time"]
BOOLEAN_TRUE  = cfg["sqli"]["boolean_true"]
BOOLEAN_FALSE = cfg["sqli"]["boolean_false"]
BOOLEAN_WRAPPERS = cfg["sqli"]["boolean_wrappers"]
BOOLEAN_SUCCESS_KEYWORDS = cfg["sqli"]["boolean_success_keywords"]
BOOLEAN_FAILURE_KEYWORDS = cfg["sqli"]["boolean_failure_keywords"]
TIMING_BASELINE_PROBES = cfg["sqli"]["timing_baseline_probes"]
TIMING_PAYLOAD_TRIALS  = cfg["sqli"]["timing_payload_trials"]
TIMING_CONFIRM_PROBES  = cfg["sqli"]["timing_confirm_probes"]

AUTO_SUBMIT_KEYS = cfg["sqli"]["auto_submit_keys"]

def detectSQLError(body):
    """
        Detects SQL errors which highlights potential vulnerabilities
    """
    lower = (body or "").lower()

    for err in SQL:
        if err in lower:
            return True, err

    return False, None

def isBlindPayload (payload):
    """
        Checks if payload is a blind payload
    """
    low = (payload or "").lower()
    return any(mark in low for mark in BLIND_MARKERS)

def buildBooleanPayloads():
    """
        Builds boolean tue/false payload pairs for blind sqli boolean tests
    """
    payloadPairs = []
    for wrap in BOOLEAN_WRAPPERS:
        for true, false in zip(BOOLEAN_TRUE, BOOLEAN_FALSE):
            payloadPairs.append((
                wrap.format(cond=true),
                wrap.format(cond=false)
            ))
    return payloadPairs

def autoSubmits(html, params):
    """
        If there is a button summits it with the name as the field
    """
    if not html:
        return params

    lowHtml = html.lower()
    for key in AUTO_SUBMIT_KEYS:
        if key in lowHtml:
            params[key.capitalize()] = key.capitalize()
    return params

def detectSQLiBlind(baseMs, testMs, thresholdMs= TIMING_THRESHOLD_MS, factor=BLIND_FACTOR):
    """
        Detects SQLi blind by checking timing difference
    """
    if testMs <= 0 or baseMs <= 0:
        return False
    return (testMs >= baseMs * factor) and ((testMs - baseMs) >= thresholdMs)

def expandTimeToken(payload, seconds=BLIND_TIME):
    """
        Replaces __TIME__ in payload strings with the configured number of seconds
    """
    return (payload or "").replace("__TIME__", str(seconds))

def detectSQLiDiff(baseHtml, html, isNotSQLIBlind=True, true= None, false=None):
    """
        Detect SQLi content by comparing the basehtml with the html after and assessing differences/
        Detect blind SQLi by checking two word lists
    """
    b = (baseHtml or "").lower()
    h = (html or "").lower()

    if not isNotSQLIBlind:
        # Check if payloads are reflected
        if (true and true.lower() in h) or (true and true.lower() in b):
            return False
        if (false and false.lower() in h) or (false and false.lower() in b):
            return False

        hasSuccB = any(s in b for s in BOOLEAN_SUCCESS_KEYWORDS)
        hasFailB = any(f in b for f in BOOLEAN_FAILURE_KEYWORDS)
        hasSuccH = any(s in h for s in BOOLEAN_SUCCESS_KEYWORDS)
        hasFailH = any(f in h for f in BOOLEAN_FAILURE_KEYWORDS)

        # True page shows success whilst other shows fail or opposite
        if (hasSuccB and hasFailH) or (hasFailB and hasSuccH):
            return True

        return False

    if re.search(r"user id (exists|is missing) in the database", h, flags=re.I) \
            and not re.search(r"user id (exists|is missing) in the database", b, flags=re.I):
        return False

    preB, preH = b.count("<pre"), h.count("<pre")
    trB, trH = b.count("<tr"), h.count("<tr")
    tdB, tdH = b.count("<td"), h.count("<td")

    Pres = (preH - preB) >= 2
    Tabs = (trH - trB) >= 2 and (tdH - tdB) >= 2

    if Pres or Tabs:

        if Pres:
            return True

        if (trH > trB) and (tdH > tdB):
            return True

    return False

class SQLiFuzzer:

    def __init__(self, baseUrl, useCrawler=False, outputToFile= False, wordlistPath=None, isSilent= False, session=None, loginUsername=None, loginPassword=None, loginPath=None, auth=False):
        self.baseUrl = baseUrl
        self.useCrawler = useCrawler
        self.wordlistPath = wordlistPath
        self.outputToFile = outputToFile
        self.isSilent = isSilent

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

        self.payloads = loadWordlist(self.wordlistPath) if self.wordlistPath is not None else []

        self.headers = {"User-Agent": cfg["http"]["user_agent"],}
        if cfg["http"]["add_referer"]:
            self.headers["Referer"] = self.baseUrl

        self.vulnerableForms = {}
        self.lock = threading.Lock()
        self.confirmLock = threading.Lock()

        if self.auth and self.loginUsername and self.loginPassword:
            ok = login(self.session, self.baseUrl, self.loginUsername, self.loginPassword, self.loginPath)
            if not ok:
                print("[-] HTTP login in SQLi Fuzzer failed")

    def getBaseline(self, endpoint, method, fields):
        """
            Get baseline to compare if SQLi worked
        """
        try:
            if method == "POST":
                baseData = {f: "1" for f in fields}

                res = self.session.post(
                    endpoint,
                    data=baseData,
                    headers=self.headers,
                    timeout=cfg["sqli"]["timeout_blind"],
                    allow_redirects=cfg["http"]["redirects"]["baseline_post"]
                )

                baseText, baseStatus = res.text or "", res.status_code

            else:
                res = self.session.get(
                    endpoint,
                    headers=self.headers,
                    timeout=cfg["sqli"]["timeout_blind"],
                    allow_redirects=cfg["http"]["redirects"]["baseline_get"]
                )

                html = res.text or ""

                params = {f: "1" for f in fields}
                params = autoSubmits(html, params)

                res = self.session.get(
                    endpoint,
                    params=params,
                    headers=self.headers,
                    timeout=cfg["sqli"]["timeout_blind"],
                    allow_redirects=cfg["http"]["redirects"]["baseline_get"]
                )

                baseText, baseStatus = res.text or "", res.status_code

            return baseText, baseStatus

        except Exception:
            return "",0

    def getBlindBaseline(self, endpoint, method, fields, probes=TIMING_BASELINE_PROBES):
        """
            Get time baseline for blind SQLi timing
        """
        try:
            elapses = []

            if method == "POST":
                res = self.session.post(
                    endpoint,
                    headers=self.headers,
                    timeout=cfg["sqli"]["timeout_blind"],
                    allow_redirects=cfg["http"]["redirects"]["baseline_post"]
                )

                html = res.text or ""

                baseData = {f: "1" for f in fields}
                baseData = autoSubmits(html, baseData)

                for _ in range(max(1, int(probes))):
                    res = self.session.post(
                        endpoint,
                        data=baseData,
                        headers=self.headers,
                        timeout=cfg["sqli"]["timeout_blind"],
                        allow_redirects=cfg["http"]["redirects"]["baseline_post"]
                    )
                    elapses.append(res.elapsed.total_seconds() * 1000.0)


            else:
                res = self.session.get(
                    endpoint,
                    headers=self.headers,
                    timeout=cfg["sqli"]["timeout_blind"],
                    allow_redirects=cfg["http"]["redirects"]["baseline_get"]
                )

                html = res.text or ""

                params = {f: "1" for f in fields}
                params = autoSubmits(html, params)

                for _ in range(max(1, int(probes))):
                    res = self.session.get(
                        endpoint,
                        params=params,
                        headers=self.headers,
                        timeout=cfg["sqli"]["timeout_blind"],
                        allow_redirects=cfg["http"]["redirects"]["baseline_get"]
                    )
                    elapses.append(res.elapsed.total_seconds() * 1000.0)

            if not elapses:
                return 0.0

            elapses.sort()
            mid = len(elapses) //2
            return elapses[mid] if len(elapses) %2 == 1 else (elapses[mid - 1] + elapses[mid]) /2.0

        except Exception:
            return 0.0

    def SQLiFuzz(self, forms):
        """
            Takes the forms retrieved by the crawler and fuzzes them for SQLi vulnerabilities
        """

        with ThreadPoolExecutor(max_workers=cfg["concurrency"]["max_workers"]) as executor:
            for form in forms:
                tasks = []
                # To track future information for saving
                ctx = {}

                url = form.get("url")
                method = (form.get("method") or "POST").upper()
                fields = form.get("formFields") or []

                # Skip invalid form objects
                if not url or not fields:
                    continue

                # Normalize Urls
                parsed = urlparse(self.baseUrl)

                if not url.startswith("http"):
                    url = f"{parsed.scheme}://{parsed.netloc}{url}"

                # Get a baseline for later comparisons
                baseText, baseStatus = self.getBaseline(url, method, fields)

                for raw in self.payloads:
                    payload = raw
                    if method == "POST":
                        # POST form fuzzing
                        data = {}

                        for field in fields:
                            # Inject payload into fuzzable fields
                            if isFuzzableField(field):
                                data[field] = payload

                            else:
                                data[field] = "1"

                        fut = executor.submit(self.session.post, url, data=data, headers=self.headers, timeout=cfg["sqli"]["timeout_blind"], allow_redirects=cfg["http"]["redirects"]["fuzz_post"])

                        tasks.append(fut)
                        ctx[fut] = (url, payload)

                    else:
                        # GET form fuzzing
                        params = {}
                        for field in fields:
                            if isFuzzableField(field):
                                params[field] = payload

                            else:
                                params[field] = "1"

                        params = autoSubmits(baseText, params)

                        # Contruct GET requests
                        logParams = [f"{k}={quote(str(v), safe='')}" for k, v in params.items()]
                        separator = "&" if "?" in url else "?"
                        fullUrl = f"{url}{separator}{'&'.join(logParams)}"

                        fut = executor.submit(self.session.get, url, params =params, headers=self.headers, timeout=cfg["sqli"]["timeout_blind"],allow_redirects=cfg["http"]["redirects"]["fuzz_get"])

                        tasks.append(fut)
                        ctx[fut] = (fullUrl, payload)

                # collect responses as they finish
                for fut in as_completed(tasks):
                    try:
                        res = fut.result()

                    except Exception:
                        continue

                    finUrl, payload = ctx[fut]


                    body = res.text or ""
                    status = res.status_code

                    # Check for SQL Error
                    isErr, indicator = detectSQLError(body)

                    if isErr or (status != baseStatus and status >= 400):
                        pageKey = finUrl.split("?", 1)[0].split("#", 1)[0]
                        resultsKey = (pageKey, (indicator or "status_code_change"), "potential")

                        with self.lock:
                            if resultsKey not in self.vulnerableForms:
                                self.vulnerableForms[resultsKey] = {
                                    "url": pageKey,
                                    "payload": payload,
                                    "payload_samples": [payload],
                                    "status_code": status,
                                    "indicator": indicator or "status_code_change",
                                    "snippet": (body or "")[:200],
                                    "count": 1,
                                    "type": "potential",
                                }

                            else:
                                entry = self.vulnerableForms[resultsKey]
                                entry["count"] += 1
                                if len(entry["payload_samples"]) < MAX_SAMPLES_PER_GROUP:
                                    entry["payload_samples"].append(payload)
                        continue

                    # Check for valid SQLi ran code
                    if baseStatus:
                        if status != baseStatus or detectSQLiDiff(baseText, body):

                            pageKey = finUrl.split("?", 1)[0].split("#", 1)[0]
                            resultsKey = (pageKey, "detected_sql_content", "vulnerable")

                            with self.lock:
                                if resultsKey not in self.vulnerableForms:
                                    self.vulnerableForms[resultsKey] = {
                                        "url": pageKey,
                                        "payload": payload,
                                        "payload_samples": [payload],
                                        "status_code": status,
                                        "indicator": "detected_sql_content",
                                        "snippet": (body or "")[:200],
                                        "count": 1,
                                        "type": "vulnerable",
                                    }

                                else:
                                    entry = self.vulnerableForms[resultsKey]
                                    entry["count"] += 1
                                    if len(entry["payload_samples"]) < MAX_SAMPLES_PER_GROUP:
                                        entry["payload_samples"].append(payload)
        return list(self.vulnerableForms.values())

    def SQLiBlindFuzz(self, forms):
        """
            Takes the forms retrieved by the crawler and fuzzes them for SQLi blind vulnerabilities
        """

        # Build boolean true/False pairs
        boolPairs = buildBooleanPayloads()

        with (ThreadPoolExecutor(max_workers=cfg["concurrency"]["max_workers"]) as executor):
            for form in forms:
                tasks = []
                # To track future information for saving
                ctx = {}

                url = form.get("url")
                method = (form.get("method") or "POST").upper()
                fields = form.get("formFields") or []

                # Skip invalid form objects
                if not url or not fields:
                    continue

                # Normalize Urls
                parsed = urlparse(self.baseUrl)

                if not url.startswith("http"):
                    url = f"{parsed.scheme}://{parsed.netloc}{url}"

                # Get a baseline for later comparisons
                baseText, baseStatus = self.getBaseline(url, method, fields)

                for trueCond, falseCond in boolPairs:
                    pairId = f"{trueCond}|||{falseCond}"
                    if method == "POST":
                        # POST form fuzzing
                        dataTrue = {}
                        dataFalse = {}

                        for field in fields:
                            # Inject into fuzzable fields the 1 plus a true condition and a false condition
                            if isFuzzableField(field):
                                dataTrue[field] = "1" + trueCond
                                dataFalse[field] = "1" + falseCond

                            else:
                                dataTrue[field] = "1"
                                dataFalse[field] = "1"

                        futTrue = executor.submit( self.session.post, url, data=dataTrue, headers=self.headers,timeout=cfg["sqli"]["timeout_blind"], allow_redirects=cfg["http"]["redirects"]["fuzz_post"])
                        futFalse = executor.submit(self.session.post, url, data=dataFalse, headers=self.headers, timeout=cfg["sqli"]["timeout_blind"], allow_redirects=cfg["http"]["redirects"]["fuzz_post"])

                        tasks.extend([futTrue, futFalse])

                        ctx[futTrue] = ("bool_true", url, trueCond, pairId)
                        ctx[futFalse] = ("bool_false", url, falseCond, pairId)

                    else:
                        # GET form fuzzing
                        paramsTrue ={}
                        paramsFalse = {}

                        for field in fields:
                            # Inject into fuzzable fields the 1 plus a true condition and a false condition
                            if isFuzzableField(field):
                                paramsTrue[field] = "1" + trueCond
                                paramsFalse[field] = "1" + falseCond

                            else:
                                paramsTrue[field] = "1"
                                paramsFalse[field] = "1"

                        paramsTrue = autoSubmits(baseText, paramsTrue)
                        paramsFalse = autoSubmits(baseText, paramsFalse)

                        # Contruct GET requests
                        logParamsT = [f"{k}={quote(str(v), safe='')}" for k, v in paramsTrue.items()]
                        logParamsF = [f"{k}={quote(str(v), safe='')}" for k, v in paramsFalse.items()]

                        seperator = "&" if "?" in url else "?"

                        fullUrlT = f"{url}{seperator}{'&'.join(logParamsT)}"
                        fullUrlF = f"{url}{seperator}{'&'.join(logParamsF)}"

                        futTrue = executor.submit(self.session.get, url, params=paramsTrue, headers=self.headers, timeout=cfg["sqli"]["timeout_blind"], allow_redirects=cfg["http"]["redirects"]["fuzz_get"])
                        futFalse = executor.submit(self.session.get, url, params=paramsFalse, headers=self.headers,timeout=cfg["sqli"]["timeout_blind"],allow_redirects=cfg["http"]["redirects"]["fuzz_get"])

                        tasks.extend([futTrue, futFalse])

                        ctx[futTrue] = ("bool_true", fullUrlT, trueCond, pairId)
                        ctx[futFalse] = ("bool_false", fullUrlF, falseCond, pairId)

                precheckBools = {}

                for fut in as_completed(tasks):
                    kind, finUrl, condStr, pid = ctx[fut]

                    try:
                        res = fut.result()
                    except Exception:
                        continue

                    body = res.text or ""
                    status = res.status_code

                    # Store bools then check when we have both
                    if kind in ("bool_true", "bool_false"):
                        key = ("GET" if method == "GET" else "POST", url, tuple(sorted(fields)), pid)

                        if key not in precheckBools:
                            precheckBools[key] = {}

                        precheckBools[key][kind] = {
                            "body": body,
                            "status": status,
                            "url": finUrl,
                            "cond": condStr
                        }

                for key, parts in precheckBools.items():
                    if "bool_true" in parts and "bool_false" in parts:
                        true, false = parts["bool_true"], parts["bool_false"]

                        if detectSQLiDiff(true["body"], false["body"], isNotSQLIBlind= False, true=true["cond"], false=false["cond"]):

                            # Check for slight absolute length change for less false positives
                            sizeDelta = abs(len(true["body"]) - len(false["body"]))
                            if not (true["status"] != false["status"] or sizeDelta >= 1):
                                continue

                            pageKey = (true["url"] or url).split("?", 1)[0].split("#", 1)[0]
                            resultsKey = (pageKey, "blind_sql_boolean", "vulnerable")
                            payloadUsed = f'TRUE:{true["cond"]} | FALSE:{false["cond"]}'

                            with self.lock:
                                if resultsKey not in self.vulnerableForms:
                                    self.vulnerableForms[resultsKey] = {
                                        "url": pageKey,
                                        "payload": payloadUsed,
                                        "payload_samples": [payloadUsed],
                                        "status_code": true["status"],
                                        "indicator": "blind_sql_boolean",
                                        "snippet": (true["body"] or "")[:200],
                                        "count": 1,
                                        "type": "vulnerable",
                                    }

                                else:
                                    entry = self.vulnerableForms[resultsKey]
                                    entry["count"] += 1
                                    if len(entry["payload_samples"]) < MAX_SAMPLES_PER_GROUP:
                                        entry["payload_samples"].append(payloadUsed)

                # Sequentially fuzz for blind timing
                baselineMs = self.getBlindBaseline(url, method, fields)
                if baselineMs > 0.0:
                    confirmJobs = []
                    for raw in self.payloads:
                        if not isBlindPayload(raw):
                            continue

                        payload = expandTimeToken(raw)
                        targets = [f for f in fields if isFuzzableField(f)]
                        if not targets:
                            continue

                        for target in targets:

                            if method == "POST":
                                # POST form fuzzing
                                data = {}

                                for field in fields:
                                    # Inject payload into fuzzable fields
                                    if field == target:
                                        data[field] = payload

                                    else:
                                        data[field] = "1"
                                data = autoSubmits(baseText, data)

                            else:
                                # GET form fuzzing
                                params = {}
                                for field in fields:
                                    if field == target:
                                        params[field] = payload

                                    else:
                                        params[field] = "1"

                                params = autoSubmits(baseText, params)

                            # Run multiple trials to get more accurate reading
                            trialElapses = []

                            for _ in range(max(1, int(TIMING_PAYLOAD_TRIALS))):
                                try:
                                    if method == "POST":
                                        res = self.session.post(url, data= data, headers=self.headers, timeout=cfg["sqli"]["timeout_blind"], allow_redirects=cfg["http"]["redirects"]["fuzz_post"])

                                    else:
                                         res = self.session.get(url, params=params, headers= self.headers, timeout=cfg["sqli"]["timeout_blind"], allow_redirects=cfg["http"]["redirects"]["fuzz_get"])

                                    # Convert and keep only time data
                                    trialElapses.append(res.elapsed.total_seconds() * 1000.0)

                                except Exception:
                                    continue

                            if not trialElapses:
                                continue

                            # Use the median to help with anomalies
                            trialElapses.sort()
                            mid = len(trialElapses) //2
                            testMs = trialElapses[mid] if len(trialElapses) %2 == 1 else (trialElapses[mid - 1] + trialElapses[mid]) /2.0

                            if not detectSQLiBlind(baselineMs,testMs):
                                continue

                            confirmJobs.append((target, payload))

                    # Check previous hits again serially to stop other payloads having a domino effect
                    if confirmJobs:
                        with self.confirmLock:

                            confirmBaseMs = self.getBlindBaseline(url, method, fields,probes=TIMING_CONFIRM_PROBES) or baselineMs
                            finalBaseMs = min(baselineMs, confirmBaseMs)

                            if not detectSQLiBlind(finalBaseMs, testMs):
                                continue

                            for (target, payload) in confirmJobs:
                                try:
                                    if method == "POST":
                                        # POST form fuzzing
                                        data = {f: (payload if f == target else "1") for f in fields}
                                        data = autoSubmits(baseText, data)

                                        res = self.session.post(
                                            url,
                                            data=data,
                                            headers=self.headers,
                                            timeout=cfg["sqli"]["timeout_blind"],
                                            allow_redirects=cfg["http"]["redirects"]["fuzz_post"]
                                        )

                                    else:
                                        # GET form fuzzing
                                        params = {f: (payload if f == target else "1") for f in fields}
                                        params = autoSubmits(baseText, params)

                                        res = self.session.get(
                                            url,
                                            params=params,
                                            headers=self.headers,
                                            timeout=cfg["sqli"]["timeout_blind"],
                                            allow_redirects=cfg["http"]["redirects"]["fuzz_get"]
                                        )

                                except Exception:
                                    continue

                                # Confirm the timing
                                testMs = res.elapsed.total_seconds() * 1000.0
                                if not detectSQLiBlind(confirmBaseMs, testMs):
                                    continue

                                # Record the confirmed payload
                                finUrl = getattr(res, "url", url) or url
                                pageKey = finUrl.split("?", 1)[0].split("#", 1)[0]
                                resultsKey = (pageKey, "blind_sql_timing", "vulnerable")

                                with self.lock:
                                    if resultsKey not in self.vulnerableForms:
                                        self.vulnerableForms[resultsKey] = {
                                            "url": pageKey,
                                            "payload": payload,
                                            "payload_samples": [payload],
                                            "status_code": res.status_code,
                                            "indicator": "blind_sql_timing",
                                            "snippet": (res.text or "")[:200],
                                            "count": 1,
                                            "type": "vulnerable",
                                        }

                                    else:
                                        entry = self.vulnerableForms[resultsKey]
                                        entry["count"] += 1
                                        if len(entry["payload_samples"]) < MAX_SAMPLES_PER_GROUP:
                                            entry["payload_samples"].append(payload)

            return list(self.vulnerableForms.values())