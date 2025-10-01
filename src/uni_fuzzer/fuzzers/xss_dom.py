import time
import logging

from urllib.parse import urlparse, quote
from uuid import uuid4
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from requests.cookies import RequestsCookieJar

from uni_fuzzer.core.base_fuzzer import AbstractFuzzer
from uni_fuzzer.core.reporting import Finding
from uni_fuzzer.core.probes import probeDom
from uni_fuzzer.auth.auth import seleniumLogin, login
from uni_fuzzer.fuzzers.detection import detectXSS

from uni_fuzzer.core.utility import status

log = logging.getLogger(__name__)

class DomXSSFuzzer(AbstractFuzzer):
    """
        Submits payload via query then loads and checks JS for payload
    """

    def __init__(self, baseUrl, session=None, bailEvent=None, cfg=None, auth=False, loginUsername=None, loginPassword=None, loginPath=None, token=None, headers=None, headless=True):
        super().__init__(baseUrl=baseUrl, session=session, headers=headers, bailEvent=bailEvent, cfg=cfg)

        if self.cfg["http"]["add_referer"]:
            self.headers["Referer"] = self.baseUrl

        self.prePayloads = list(self.cfg["xss"]["dom_payloads"] or [])
        self.payloads = []
        self.token = token or f"XSSCanary-{uuid4().hex[:8]}"
        self.tokenLow = self.token.lower()

        self.candidates = []

        self.auth = auth
        self.loginUsername = loginUsername
        self.loginPassword = loginPassword
        self.loginPath = loginPath

        self.headless = headless

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
            Build payloads and candidates
        """
        self.payloads = []

        seen = set()
        for raw in (self.prePayloads or []):
            if raw in seen:
                continue
            seen.add(raw)
            self.payloads.append(raw.replace("{CANARY}", self.token))

        if ctx is None:
            self.candidates = []
            return

        if isinstance(ctx, dict):
            forms = ctx.get("forms")
            endpoints = ctx.get("endpoints")
        else:
            forms = getattr(ctx, "forms", None)
            endpoints = getattr(ctx, "endpoints", None)

        parsed = urlparse(self.baseUrl)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Build candidates
        cand = []

        for form in (forms or []):
            # Build URLs from forms
            url = form.get("url")
            method = (form.get("method") or "GET").upper()
            fields = form.get("formFields") or []

            # Only fuzz get forms with fields
            if not url or method != "GET" or not fields:
                continue
            if not url.startswith("http"):
                url = f"{origin}{url}"

            # Try all DOM specific payloads
            for raw in (self.prePayloads or []):
                marked = raw.replace("{CANARY}", self.token)
                parts = [f"{field}={quote(marked, safe='')}" for field in fields]
                separator = "&" if "?" in url else "?"
                cand.append((f"{url}{separator}{'&'.join(parts)}", raw, marked))
                cand.append((f"{url}#{quote(marked, safe='')}", raw, marked))

        for ep in (endpoints or []):
            # Build URLs from endpoints
            if not isinstance(ep, dict):
                continue

            rawUrl = ep.get("url")
            params = list(ep.get("params") or [])

            if not rawUrl or not params:
                continue

            # Normalize URLs
            fullUrl = rawUrl if rawUrl.startswith("http") else f"{origin}{rawUrl}"

            for raw in (self.prePayloads or []):
                marked = raw.replace("{CANARY}", self.token)
                parts = [f"{p}={quote(marked, safe='')}" for p in params]
                sep = "&" if "?" in fullUrl else "?"
                cand.append((f"{fullUrl}{sep}{'&'.join(parts)}", raw, marked))
                cand.append((f"{fullUrl}#{quote(marked, safe='')}", raw, marked))

        dedup = {}
        for (u, raw, marked) in cand:
            pageKey = u.split("?", 1)[0].split("#", 1)[0]
            dedup.setdefault((pageKey, raw), (u, raw, marked))
        self.candidates = list(dedup.values())


    def run(self, ctx):
        """
            Build batch and execute via runBatch
        """
        self.prepare(ctx)

        parsed = urlparse(self.baseUrl)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        candidates = self.candidates or []
        if not candidates:
            return []

        # Configure the selenium webdriver
        options = Options()
        if self.headless:
            options.headless = True
            options.add_argument("--headless=new")
        options.add_argument("--window-size=1920,1080")

        # TO silence console
        options.add_argument("--log-level=3")
        options.add_experimental_option("excludeSwitches", ["enable-logging"])

        findings = {}
        seen = set()
        pageRep = set() if self.bailEvent is not None else None

        driver = None
        try:
            driver = webdriver.Chrome(options=options)
            try:
                # Extra to match cookies from initial session
                driver.get(origin)

                if getattr(self, "session", None):
                    for c in self.session.cookies:
                        name = getattr(c, "name", None)
                        value = getattr(c, "value", None)
                        if not name or not value:
                            continue

                        domain = (getattr(c, "domain", "") or "").lstrip(".")
                        path = getattr(c, "path", "/") or "/"

                        # only push cookies that match the current origin
                        if domain and not parsed.netloc.endswith(domain):
                            continue

                        ck = {"name": name, "value": value, "path": path, "domain": domain}
                        exp = getattr(c, "expires", None)

                        if exp is not None:
                            try:
                                ck["expiry"] = int(exp)
                            except Exception:
                                log.debug("Cookie expiry conversion failed ", exc_info=True)

                        try:
                            driver.add_cookie(ck)
                        except Exception:
                            log.debug("driver.add_cookie failed: %s", ck, exc_info=True)
            except Exception:
                log.debug("Preloading origin & cookie copy failed", exc_info=True)

            # If selenium login true
            if self.auth:
                baseForLogin = f"{parsed.scheme}://{parsed.netloc}"

                if not seleniumLogin(
                        driver,
                        baseUrl=baseForLogin,
                        username=self.loginUsername,
                        password=self.loginPassword,
                        loginPath=self.loginPath,
                        selectors=None
                ):
                    status("[!] Selenium login failed")
                    log.warning("Selenium login failed during domXSS")
                    return []

                try:
                    jar = RequestsCookieJar()
                    for c in driver.get_cookies():
                        name, value = c.get("name"), c.get("value")
                        domain, path = c.get("domain"), c.get("path") or "/"

                        if name and value:
                            jar.set(name=name, value=value, domain=domain, path=path)

                    if getattr(self, "session", None):
                        try:
                            self.session.cookies.update(jar)
                        except Exception:
                            log.debug("Copying cookies from driver back to session failed during updating", exc_info=True)
                except Exception:
                    log.debug("Copying cookies from driver back to session failed during collection", exc_info=True)

            for finUrl, raw, marked in candidates:
                # If bail on first then bail
                if self.bailEvent and self.bailEvent.is_set():
                    break
                # Normalize the page key
                pageKey = finUrl.split("?", 1)[0].split("#", 1)[0]

                if pageRep is not None and pageKey in pageRep:
                    continue

                if (pageKey, raw) in seen:
                    # Skip already tested pages
                    continue
                seen.add((pageKey, raw))

                try:
                    driver.get(finUrl)
                    # time set in config/defaults
                    time.sleep(self.cfg["xss"]["dom_delay_seconds"])

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
                        ok, _ = detectXSS(src, self.token)
                        if not ok:
                            indicator = None

                    if not indicator:
                        continue

                    # record result
                    resultsKey = (pageKey, indicator)

                    if resultsKey not in findings:

                        findings[resultsKey] = Finding(
                            type="xss_dom",
                            url=pageKey,
                            method="GET",
                            param=None,
                            payload=raw,
                            indicator=indicator,
                            status_code=200,
                            count=1,
                            payload_samples=[raw],
                            response_snippet=(driver.page_source or "")[:200]
                        )
                        setattr(findings[resultsKey], "bail", True)
                        if pageRep is not None:
                            pageRep.add(pageKey)
                        if self.bailEvent:
                            try:
                                self.bailEvent.set()
                            except:
                                pass
                    else:
                        find = findings[resultsKey]
                        find.count = (find.count or 0) + 1
                        if raw not in (find.payload_samples or []):
                            if len(find.payload_samples or []) < self.cfg["xss"]["max_samples_per_group"]:
                                find.payload_samples.append(raw)

                except Exception:
                    log.debug("DOM candidate failed for %s", finUrl, exc_info=True)
                    continue
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    log.debug("driver.quit() failed", exc_info=True)

        return list(findings.values())


    def analyzeResponse(self, response, meta):
        """
            analyze the response for dom XSS
        """
        pass