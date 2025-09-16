import requests
import time
from urllib.parse import urljoin, urlparse, quote, unquote_plus
from uuid import uuid4
from html import unescape
from concurrent.futures import ThreadPoolExecutor, as_completed
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from requests.cookies import RequestsCookieJar
from requests.adapters import HTTPAdapter
from threading import Lock

from uni_fuzzer.core.probes import probeDom, probeReflexivity
from uni_fuzzer.auth.auth import seleniumLogin, login
from uni_fuzzer.core.baseline import baselineForm
from uni_fuzzer.fuzzers.detection import detectXSS

from uni_fuzzer.core.utility import get_cfg, isFuzzableField, loadWordlist, autoSubmits, canary
cfg = get_cfg()

# To avoid duplicate hits on page visits
_REPORTED_STORED_KEYS = {}
reportLock = Lock()

DOM_PAYLOADS = cfg["xss"]["dom_payloads"]

MAX_SAMPLES_PER_GROUP = cfg["xss"]["max_samples_per_group"]

class XSSFuzzer:

    def __init__(self, baseUrl, useCrawler = False, outputToFile= False, wordlistPath=None, isSilent=False, headless= True, session=None, loginUsername=None, loginPassword=None, loginPath=None, auth=False, token= None):
        self.baseUrl = baseUrl
        self.useCrawler = useCrawler
        self.wordlistPath = wordlistPath
        self.outputToFile = outputToFile
        self.payloads = loadWordlist(self.wordlistPath) if self.wordlistPath is not None else []
        self.isSilent = isSilent
        self.token = token or f"XSSCanary-{uuid4().hex[:8]}"
        self.headless = headless

        self.tokenLow = self.token.lower()
        self.tokenB = self.token.encode("utf-8", errors="ignore")

        self.session = session or requests.Session()
        if session is None:
            mw = int(cfg["concurrency"]["max_workers"])
            adapter = HTTPAdapter(pool_connections=mw, pool_maxsize=mw, max_retries=0)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
            self.session.trust_env = False
        self.headers = {"User-Agent": cfg["http"]["user_agent"]}

        if cfg["http"]["add_referer"]:
            self.headers["Referer"] = self.baseUrl

        self.loginUsername = loginUsername
        self.loginPassword = loginPassword
        self.loginPath = loginPath
        self.auth = auth

        self.vulnerableParams = []

        if self.loginUsername and self.loginPassword and self.auth:
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
                print("[-] HTTP login in XSSFuzzer failed")


    def sendRequest(self, url, payload=None, markedPayload= None, method="GET", data=None):
        """
            Send a single GET request and check for success
        """
        try:
            if method == "POST":
                response = self.session.post( url, data=data, headers=self.headers, timeout=cfg["http"]["timeout_get_seconds"], allow_redirects=cfg["http"]["redirects"]["submit"])

            else:
                response = self.session.get(url, headers=self.headers, timeout=cfg["http"]["timeout_get_seconds"], allow_redirects=cfg["http"]["redirects"]["fuzz_get"])

            ctype = (response.headers.get("Content-Type") or "").lower()
            if ctype and ("html" not in ctype and "xml" not in ctype and "javascript" not in ctype):
                return None

            content = response.content or b""

            if self.tokenB not in content:
                return None

            enc = response.encoding or "utf-8"
            body = content.decode(enc, errors="ignore")

            # deeper XSS detection
            ok, indicator = detectXSS(body, self.token, markedPayload)
            if ok:
                result = {
                    "url": url,
                    "payload": payload,
                    "status_code": response.status_code,
                    "indicator": indicator or "N/A",
                    "snippet": body[:200],
                }
                self.vulnerableParams.append(result)
                return {"type": "vulnerable", "data": result}

        except requests.exceptions.Timeout:
            # When fuzzing large endpoints timeouts overwhelm, disable if needed
            pass

        except requests.RequestException as e:
            if not self.isSilent:
                print(f"[!] Request failed for {url}: {e}")

        return None

    def paramXSS(self):
        """
            Fuzz query params for reflected XSS
        """
        parsed = urlparse(self.baseUrl)

        # Only fuzz if fuzz in query
        if "FUZZ" not in parsed.query:
            print("[-] No 'FUZZ' keyword found")
            return []

        # Reconstruct base URL without query
        baseNoQuery = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        originalQuery = parsed.query

        # Prebuilding to remove multiple canary and quote calls
        prebuiltPayloads = []
        seen = set()

        for raw in self.payloads:
            if raw in seen:
                continue

            seen.add(raw)
            marked = canary(raw, self.token)
            enc = quote(marked, safe="")
            prebuiltPayloads.append((raw, marked, enc))

        # Singular probe to check if reflective
        probe = f"xssprobe-{self.token}"
        probeQuery = originalQuery.replace("FUZZ", quote(probe, safe=""))
        probeUrl = f"{baseNoQuery}?{probeQuery}"

        try:
            res = self.session.get(
                probeUrl,
                headers=self.headers,
                timeout=cfg["http"]["timeout_get_seconds"],
                allow_redirects=False
            )
            body = res.text or ""

            if probe.lower() not in body.lower() and unescape(body).lower().find(probe.lower()) == -1:
                return []

        except Exception:
            return []

        tasks = []
        results = {}

        with ThreadPoolExecutor(max_workers=cfg["concurrency"]["max_workers"]) as executor:
            for raw, marked, enc in prebuiltPayloads:
                # Replace FUZZ with the payload, uniquely mark it, encode it for URL injection
                fuzzedQuery = originalQuery.replace("FUZZ", enc)
                fullUrl = f"{baseNoQuery}?{fuzzedQuery}"

                tasks.append(executor.submit(self.sendRequest, fullUrl,payload=raw, markedPayload=marked))

            # Collect results as requests complete
            for future in as_completed(tasks):

                out = future.result()

                if not out or "data" not in out:
                    continue

                data = out["data"]
                finUrl = data.get("url") or ""
                indicator = data.get("indicator") or "N/A"
                raw = data.get("payload")

                pageKey = finUrl.split("?", 1)[0].split("#", 1)[0]
                resultsKey = (pageKey, indicator)

                if resultsKey not in results:

                    results[resultsKey] = {
                        "url": pageKey,
                        "payload": raw,
                        "payload_samples": [raw],
                        "status_code": data.get("status_code"),
                        "indicator": indicator or "N/A",
                        "snippet": (data.get("snippet") or "")[:200],
                        "count": 1,
                        "type": "xss_param"
                    }
                else:
                    entry = results[resultsKey]
                    entry["count"] += 1
                    # Cap the examples
                    if len(entry["payload_samples"]) < MAX_SAMPLES_PER_GROUP:
                        entry["payload_samples"].append(raw)

        return list(results.values())

    def formXSS(self, forms):
        """
            Takes the forms retrieved by the crawler and fuzzes them for reflected XSS
        """
        results = {}

        # Prebuilding to remove multiple canary and quote calls
        prebuiltPayloads = []
        seen = set()

        for raw in self.payloads:
            if raw in seen:
                continue

            seen.add(raw)
            marked = canary(raw, self.token)
            enc = quote(marked, safe="")
            prebuiltPayloads.append((raw, marked, enc))

        with ThreadPoolExecutor(max_workers=cfg["concurrency"]["max_workers"]) as executor:
            for form in forms:
                tasks = []

                url = form.get("url")
                method = (form.get("method") or "POST").upper()
                fields = form.get("formFields") or[]

                # Skip invalid form objects
                if not url or not fields:
                    continue

                # Normalize Url
                parsed = urlparse(self.baseUrl)
                if not url.startswith("http"):
                    url = f"{parsed.scheme}://{parsed.netloc}{url}"

                fuzzField = [f for f in fields if isFuzzableField(f)]

                if not fuzzField:
                    continue

                # Singular probe to check if reflective
                if not probeReflexivity(self.session, url, method, fields, fuzzField, self.headers, self.token):
                    continue

                # Get baseline to check for submit buttons
                base = baselineForm(self.session, url, self.headers)
                baseHtml = base["content"]

                if method == "POST":
                    # POST form fuzzing
                    baseD = {f: "test" for f in fields}
                    baseD = autoSubmits(baseHtml, baseD)
                    for raw, marked, _enc in prebuiltPayloads:
                        data = baseD.copy()
                        for f in fuzzField:
                            data[f] = marked

                        fut = executor.submit(self.sendRequest, url, raw, marked, "POST", data)
                        tasks.append(fut)

                else:
                    # GET form fuzzing
                    baseP = {f: "test" for f in fields}
                    separator = "&" if "?" in url else "?"

                    for raw, marked, enc in prebuiltPayloads:
                        params = dict(baseP)
                        for f in fuzzField:
                            params[f] = enc

                        logParams = [f"{k}={quote(str(v), safe='')}" for k, v in params.items()]
                        fullUrl = f"{url}{separator}{'&'.join(logParams)}"

                        fut = executor.submit(self.sendRequest, fullUrl, raw, marked, "GET", None)
                        tasks.append(fut)

                # collect responses at end
                for fut in as_completed(tasks):
                    try:
                        res = fut.result()

                    except Exception:
                        continue

                    if not res or "data" not in res:
                        continue

                    data = res["data"]
                    finUrl = data.get("url") or url
                    pageKey = finUrl.split("?", 1)[0].split("#", 1)[0]
                    indicator = data.get("indicator") or "N/A"

                    resultsKey = (pageKey, indicator)

                    if resultsKey not in results:

                        results[resultsKey] = {
                            "url": pageKey,
                            "payload": raw,
                            "payload_samples": [raw],
                            "status_code": data.get("status_code"),
                            "indicator": indicator,
                            "snippet": (data.get("snippet") or "")[:200],
                            "count": 1,
                            "type": "xss_form"
                        }
                    else:
                        entry = results[resultsKey]
                        entry["count"] += 1
                        # Cap the examples
                        if len(entry["payload_samples"]) < MAX_SAMPLES_PER_GROUP:
                            entry["payload_samples"].append(raw)

            return list(results.values())


    def storedXSS(self, forms,endpoints=None):
        """
            Submits payload then revisits to see if payload still there
        """
        results = {}
        pages = set()

        # Prebuilding to remove multiple canary and quote calls
        prebuiltPayloads = []
        seen = set()

        for raw in self.payloads:
            if raw in seen:
                continue

            seen.add(raw)
            marked = canary(raw, self.token)
            enc = quote(marked, safe="")
            prebuiltPayloads.append((raw, marked, enc))

        with ThreadPoolExecutor(max_workers=cfg["concurrency"]["max_workers"]) as executor:
            for form in forms:
                tasks = []
                ctx = {}

                url = form.get("url")
                method = (form.get("method") or "POST").upper()
                fields = form.get("formFields") or []

                if not url or not fields:
                    continue

                # Normalize Url
                parsed = urlparse(self.baseUrl)
                if not url.startswith("http"):
                    url = f"{parsed.scheme}://{parsed.netloc}{url}"

                # Track the form to potentially revisit
                pages.add(url)

                # Get baseline to check for submit buttons
                base = baselineForm(self.session, url, self.headers)
                baseHtml = base["content"]

                for raw, marked, enc in prebuiltPayloads:

                    if method == "POST":
                        # POST form fuzzing
                        data = {}

                        for field in fields:
                            if isFuzzableField(field):
                                data[field] = marked

                            else:
                                data[field] = "test"

                        data = autoSubmits(baseHtml, data)

                        fut = executor.submit(self.session.post, url, data=data, headers=self.headers, timeout=cfg["http"]["timeout_get_seconds"],allow_redirects=cfg["http"]["redirects"]["submit"])

                        tasks.append(fut)
                        ctx[fut] = (url,raw,marked)

                    else:
                        # GET form fuzzing
                        params = {}

                        for field in fields:
                            if isFuzzableField(field):
                                params[field] = enc

                            else:
                                params[field] = "test"


                        separator = "&" if "?" in url else "?"
                        logParams = [f"{k}={quote(str(v), safe='')}" for k, v in params.items()]
                        fullUrl = f"{url}{separator}{'&'.join(logParams)}"

                        fut = executor.submit(self.session.get, fullUrl, headers=self.headers, timeout=cfg["http"]["timeout_get_seconds"],allow_redirects=cfg["http"]["redirects"]["submit"])

                        tasks.append(fut)
                        ctx[fut] = (fullUrl, raw, marked)

                # Collect results
                for fut in as_completed(tasks):
                    try:
                        res = fut.result()

                    except Exception:
                        continue

                    finUrl, raw, marked = ctx[fut]

                    # Add final URL to revisit list
                    try:
                        if getattr(res, "url", None):
                            pages.add(res.url)
                    except Exception:
                        pass

                    pages.add(finUrl)

                    # Follow redirections after submitting form
                    if res.status_code in (301, 302, 303,307, 308):
                        loc = res.headers.get("Location")
                        if loc:
                            pages.add(loc if loc.startswith("http")else urljoin(finUrl, loc))

        # Merge extra endpoints
        if endpoints:
            parsed = urlparse(self.baseUrl)
            base = f"{parsed.scheme}://{parsed.netloc}"

            for end in endpoints:
                if not end:
                    continue

                pages.add(end if end.startswith("http") else f"{base}{end}")

        # Prebuild marked payloads
        markedPayloads = [(raw, canary(raw, self.token)) for raw in self.payloads]

        # Revisit collected pages
        with ThreadPoolExecutor(max_workers=cfg["concurrency"]["max_workers"]) as executor:

            futToPage = {
                executor.submit(
                    self.session.get,
                    page,
                    headers=self.headers,
                    timeout=cfg["http"]["timeout_get_seconds"],
                    allow_redirects=cfg["http"]["redirects"]["stored_xss"]
                ): page
                for page in pages
            }

            for fut in as_completed(futToPage):

                finUrl = futToPage[fut]
                try:
                    res = fut.result()

                except Exception:
                    continue

                body = res.text or ""
                low = body.lower()
                lowU = unescape(body).lower()
                lowQ = unquote_plus(body).lower()

                # If no token at all continue
                if (self.tokenLow not in low) and (self.tokenLow not in lowU) and (self.tokenLow not in lowQ):
                    continue

                # Check if payloads still persists
                for raw, marked in markedPayloads:
                    # To remove duplicates from different flows
                    rawKey = finUrl.split("?", 1)[0].split("#", 1)[0]
                    try:
                        p = urlparse(rawKey)
                        scheme = (p.scheme or "").lower()
                        netloc = (p.netloc or "").lower()
                        path = p.path or "/"

                        if path != "/" and path.endswith("/"):
                            path = path.rstrip("/")
                        pageKey = f"{scheme}://{netloc}{path}"

                    except Exception:
                        base = finUrl.split("?", 1)[0].split("#", 1)[0]
                        pageKey = (base.rstrip("/")).lower()

                    ok, indicator = detectXSS(res.text, self.token, marked)
                    if ok:
                        # Check if reported before
                        pageInd = (pageKey, indicator or "N/A", marked)
                        with reportLock:
                            bucket = _REPORTED_STORED_KEYS.setdefault(self.token, set())
                            if pageInd in bucket:
                                continue
                            bucket.add(pageInd)

                        resultsKey = (pageKey, (indicator or "N/A"), "xss_stored")
                        if resultsKey not in results:
                            results[resultsKey] = {
                                "url": pageKey,
                                "payload": raw,
                                "payload_samples": [raw],
                                "status_code": res.status_code,
                                "indicator": indicator,
                                "snippet": (res.text or "")[:200],
                                "count": 1,
                                "type": "xss_stored",
                            }
                        else:
                            entry = results[resultsKey]
                            entry["count"] += 1
                            if len(entry["payload_samples"]) < MAX_SAMPLES_PER_GROUP:
                                entry["payload_samples"].append(raw)

        return list(results.values())
                        # Add break if you just want to see its vulnerable, without lists all successful payloads
                        #break


    def domXSS(self, forms= None, endpoints= None):
        """
            Submits payload via query then loads and checks JS for payload
        """
        results = {}

        parsedBase = urlparse(self.baseUrl)
        base = f"{parsedBase.scheme}://{parsedBase.netloc}"

        candidates = []

        if forms:
            # Build URLs from forms
            for form in forms:

                url = form.get("url")
                method = (form.get("method") or "GET").upper()
                fields = form.get("formFields") or[]

                # Only fuzz get forms with fields
                if not url or method != "GET" or not fields:
                    continue

                # Normalize relative form URLs
                if not url.startswith("http"):
                    url = f"{base}{url}"

                # Try all DOM specific payloads
                for raw in DOM_PAYLOADS:
                    marked = raw.replace("{CANARY}", self.token)
                    parts = []

                    for field in fields:
                        parts.append(f"{field}={quote(marked, safe='')}")

                    seperator = "&" if "?" in url else "?"
                    candidates.append((f"{url}{seperator}{'&'.join(parts)}", raw, marked))
                    candidates.append((f"{url}#{quote(marked, safe='')}", raw, marked))

        if endpoints:
            # Build URLs from endpoints
            for ep in endpoints:
                rawUrl = ep.get("url")
                params = ep.get("params") or []

                if not rawUrl or not params:
                    continue

                # Normalize URLs
                fullUrl = rawUrl if rawUrl.startswith("http") else f"{base}{rawUrl}"

                # Randomly sample the dom_payloads to save time
                chosenPayloads = DOM_PAYLOADS

                # Try chosen DOM specific payloads
                for raw in chosenPayloads:
                    marked = raw.replace("{CANARY}", self.token)
                    parts = [f"{p}={quote(marked,safe='')}" for p in params]
                    seperator = "&" if "?" in fullUrl else "?"
                    candidates.append((f"{fullUrl}{seperator}{'&'.join(parts)}", raw, marked))
                    candidates.append((f"{fullUrl}#{quote(marked, safe='')}", raw, marked))

        # If no fuzzable URLs found then return empty
        if not candidates:
            return list(results.values())

        # Configure the selenium webdriver
        options = Options()
        if self.headless:
            options.headless = True
            options.add_argument("--headless=new")
        options.add_argument("--window-size=1920,1080")

        # TO silence console
        options.add_argument("--log-level=3")
        options.add_experimental_option("excludeSwitches", ["enable-logging"])

        driver = webdriver.Chrome(options=options)
        try:
            try:
                # Extra to match cookies from initial session
                parse = urlparse(self.baseUrl)
                origin = f"{parse.scheme}://{parse.netloc}"
                driver.get(origin)

                for c in self.session.cookies:
                    name = getattr(c, "name", None)
                    value = getattr(c, "value", None)
                    if not name or not value:
                        continue

                    domain = (getattr(c, "domain", "") or "").lstrip(".")
                    path = getattr(c, "path", "/") or "/"

                    # only push cookies that match the current origin
                    if domain and not parse.netloc.endswith(domain):
                        continue

                    ck = {"name": name, "value": value, "path": path, "domain": domain}
                    exp = getattr(c, "expires", None)

                    if exp is not None:
                        try:
                            ck["expiry"] = int(exp)
                        except Exception:
                            pass

                    try:
                        driver.add_cookie(ck)
                    except Exception:
                        pass
            except Exception:
                pass
            # If selenium login true
            if self.auth and self.loginUsername and self.loginPassword:

                base = f"{urlparse(self.baseUrl).scheme}://{urlparse(self.baseUrl).netloc}"

                if not seleniumLogin(
                        driver,
                        baseUrl=base,
                        username=self.loginUsername,
                        password=self.loginPassword,
                        loginPath=self.loginPath,
                        selectors=None
                ):
                    if not self.isSilent:
                        print("[-] Selenium login failed")
                    return list(results.values())

                try:
                    jar = RequestsCookieJar()
                    for c in driver.get_cookies():
                        name, value = c.get("name"), c.get("value")
                        domain, path = c.get("domain"), c.get("path") or "/"

                        if name and value:
                            jar.set(name=name, value=value, domain=domain, path=path)

                    self.session.cookies.update(jar)

                except Exception:
                    pass


            seen = set()
            for finUrl, raw, marked in candidates:
                # Normalize the page key
                pageKey = finUrl.split("?", 1)[0].split("#", 1)[0]

                if (pageKey, raw) in seen:
                    # Skip already tested pages
                    continue
                seen.add((pageKey, raw))

                try:
                    driver.get(finUrl)
                    # time set in config/defaults
                    time.sleep(cfg["xss"]["dom_delay_seconds"])

                    # Check for DOM XSS
                    flag = probeDom(driver, self.tokenLow)

                    # Add specific indicators
                    indicator = None
                    if flag.get("gflag"):
                        indicator = "dom_global_flag"
                    elif flag.get("el"):
                        indicator = "dom_element_ctx"
                    elif flag.get("ls") or flag.get("ss"):
                        indicator = "dom_storage"

                    # To resolve false positives for dom_storage
                    if indicator == "dom_storage":
                        src = driver.page_source or ""
                        ok, _ = detectXSS(src, self.token, self.token)
                        if not ok:
                            continue

                    # try retrigger hash based then add indicators
                    if not indicator:
                        try:
                            driver.execute_script("location.hash = arguments[0];", "#" + quote(marked, safe=""))
                            time.sleep(cfg["xss"]["dom_delay_seconds"])
                            flag2 = probeDom(driver, self.tokenLow)
                            if flag2.get("gflag"):
                                indicator = "dom_global_flag_hash"
                            elif flag2.get("el"):
                                indicator = "dom_element_ctx_hash"
                            elif flag2.get("ls") or flag2.get("ss"):
                                indicator = "dom_storage_hash"

                            # To resolve false positives for dom_storage
                            if indicator == "dom_storage_hash":
                                src = driver.page_source or ""
                                ok, _ = detectXSS(src, self.token, self.token)
                                if not ok:
                                    continue

                        except Exception:
                            pass

                        if not indicator:
                            continue

                    # record result
                    pageKey = finUrl.split("?", 1)[0].split("#", 1)[0]
                    resultsKey = (pageKey, (indicator or "N/A"))

                    if resultsKey not in results:

                        results[resultsKey] = {
                            "url": pageKey,
                            "payload": raw,
                            "payload_samples": [raw],
                            "status_code": 200,
                            "indicator": indicator ,
                            "snippet": (driver.page_source or "")[:200],
                            "count": 1,
                            "type": "xss_dom"
                        }
                    else:
                        entry = results[resultsKey]
                        entry["count"] += 1
                        # Cap the examples
                        if len(entry["payload_samples"]) < MAX_SAMPLES_PER_GROUP:
                            entry["payload_samples"].append(raw)

                except Exception:
                    continue
        finally:
            driver.quit()

        return list(results.values())
