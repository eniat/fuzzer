import requests
import time
import logging
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urldefrag
from requests.cookies import RequestsCookieJar
from requests.adapters import HTTPAdapter

from uni_fuzzer.auth.auth import seleniumLogin, login

from uni_fuzzer.core.utility import get_cfg, extractIdentifier, status
cfg = get_cfg()

log = logging.getLogger(__name__)

class Crawler:

    def __init__(self, mode=None, maxPages=None, rateLimit=None, headless=None, outputToFile=None, auth=False, loginUsername=None, loginPassword=None, loginPath=None):
        # Crawler settings
        self.mode = mode or cfg["crawler"]["mode_default"]
        self.maxPages = maxPages if maxPages is not None else cfg["crawler"]["max_pages_default"]
        self.rateLimit = rateLimit if rateLimit is not None else cfg["crawler"]["rate_limit_default"]
        self.headless = headless if headless is not None else cfg["crawler"]["headless_default"]
        self.outputToFile = outputToFile if outputToFile is not None else cfg["crawler"]["output_to_file_default"]

        self.auth = auth
        self.loginUsername = loginUsername
        self.loginPassword = loginPassword
        self.loginPath = loginPath

        # Storage for results
        self.discoveredEndpoints = []
        self.discoveredForms = []

        self.session = requests.Session()

        mw = int(cfg["concurrency"]["max_workers"])
        adapter = HTTPAdapter(pool_connections=mw, pool_maxsize=mw, max_retries=0)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.trust_env = False

        self.driver = None

    def crawl (self, startUrl):
        """
            Crawl from starting url using the set mode, either static or dynamic
            return self.discoveredEndpoints, self.discoveredForms
        """

        self.discoveredEndpoints = []
        self.discoveredForms = []
        endpointsMap = {}
        formsMap = {}

        # Extract domain from start
        domain = urlparse(startUrl).netloc

        if self.auth and self.loginUsername and self.loginPassword and self.mode in ("static", "both"):
            ok = login(
                self.session,
                startUrl,
                self.loginUsername,
                self.loginPassword,
                self.loginPath
            )
            if not ok:
                status("[!] HTTP login failed"); log.warning("HTTP login failed")

        # Static Crawl, if either the mode is static or both
        if self.mode in ('static', 'both'):
            staticEndpoints, staticForms = self.crawlStatic(startUrl,domain)

            # Merge static results
            for ep in staticEndpoints:
                path = ep["url"]
                params = ep.get("params", [])
                endpointsMap.setdefault(path, set()).update(params)

            for fm in staticForms:
                path = fm["url"]
                method = fm.get("method", "GET").upper()
                fields = fm.get("formFields", [])
                formsMap.setdefault((path, method), set()).update(fields)

        # Dynamic Crawl, if either mode is dynamic or both
        if self.mode in ('dynamic', 'both'):
            dynamicEndpoints, dynamicForms = self.crawlDynamic(startUrl, domain)

            # Merge dynamic results
            for ep in dynamicEndpoints:
                path = ep["url"]
                params = ep.get("params", [])
                endpointsMap.setdefault(path, set()).update(params)

            for fm in dynamicForms:
                path = fm["url"]
                method = fm.get("method", "GET").upper()
                fields = fm.get("formFields", [])
                formsMap.setdefault((path, method), set()).update(fields)

        # Convert to lists of dics for output
        for path, paramsSet in endpointsMap.items():
            self.discoveredEndpoints.append({"url": path, "method": "GET", "params": list(paramsSet)})

        for (path, method), fieldsSet in formsMap.items():
            self.discoveredForms.append({"url": path, "method": method, "formFields": list(fieldsSet)})

        return self.discoveredEndpoints, self.discoveredForms


    def crawlStatic(self, startUrl, domain):
        """
            Static crawl fetches pages with requests and parses HTML with BeautifulSoup
            return endpointDicts, staticForms
        """

        queue = [startUrl]
        visited = {startUrl}
        staticEndpoints = set()
        staticForms = []
        pagesCrawled = 0

        while queue:
            currentUrl = queue.pop(0)
            if self.maxPages and pagesCrawled >= self.maxPages:
                break
            try:
                response = self.session.get(currentUrl,timeout=cfg["http"]["crawl_get"])
            except requests.RequestException:
                # On error requesting notify
                log.debug("Request failed during crawl", exc_info=True)
                continue
            if response.status_code != 200:
                #Skips non OK pages
                continue

            if self.rateLimit:
                time.sleep(self.rateLimit)

            # Only parse HTML
            contentType = response.headers.get("Content-Type", "")
            if "text/html" not in contentType:
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            # Extract <a href> links
            for a in soup.find_all('a', href= True):
                href = a['href']

                if href.startswith('mailto:') or href.startswith('javascript:') or href.startswith('#'):
                    # If its #ect then record route and params
                    if href.startswith('#'):
                        frag = href[1:]
                        if frag.startswith('/'):
                            # Split fragment into path and query string
                            fragPath, _, fragQuery = frag.partition('?')
                            params = list(parse_qs(fragQuery).keys()) if fragQuery else []
                            routePath = "/#" + fragPath.lstrip('/')
                            staticEndpoints.add((routePath, "GET", tuple(params)))
                    continue

                # Convert URL to absolute
                absUrl = urljoin(currentUrl, href)

                # Make sure link is within the base domain and hasn't been visited
                if urlparse(absUrl).netloc == domain and absUrl not in visited:
                    visited.add(absUrl)
                    queue.append(absUrl)

                # Record endpoint and any query parameters
                parsed = urlparse(absUrl)
                params = list(parse_qs(parsed.query).keys()) if parsed.query else []
                endpointPath = parsed.path or "/"
                if parsed.fragment:
                    endpointPath += "#" + parsed.fragment
                staticEndpoints.add((endpointPath, "GET", tuple(params)))

            # Find other resources like img with src attributes
            for tag in soup.find_all(['script', 'img'], src=True):
                src = tag['src']

                if src.startswith('javascript:') or src.startswith('data:'):
                    continue

                absSrc = urljoin(currentUrl, src)
                absSrc = urldefrag(absSrc)[0]

                if urlparse(absSrc).netloc == domain and absSrc not in visited:
                    visited.add(absSrc)
                    queue.append(absSrc)

                parsedSrc = urlparse(absSrc)
                params = list(parse_qs(parsedSrc.query).keys()) if parsedSrc.query else []
                endpointPath = parsedSrc.path or "/"
                staticEndpoints.add((endpointPath, "GET", tuple(params)))

            #Look for  forms and parse
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()

                # Determine abs url
                if action and not action.startswith('javascript:'):
                    actionUrl = urljoin(currentUrl, action)
                else:
                    actionUrl = currentUrl

                actionUrl = urldefrag(actionUrl)[0]
                parsedAction = urlparse(actionUrl)

                # Only forms on the same domain
                if parsedAction.netloc and parsedAction.netloc != domain:
                    continue

                formPath = f"{parsedAction.scheme}://{parsedAction.netloc}{parsedAction.path or '/'}"
                if parsedAction.fragment:
                    formPath += "#" + parsedAction.fragment

                # Get clean identifiers
                fields = []
                for inp in form.find_all(['input', 'textarea', 'select']):
                    identifier = extractIdentifier(inp)
                    if identifier:
                        fields.append(identifier)

                # Get all input fields
                staticForms.append({"url": formPath, "method": method, "formFields": fields})

                # Check for links hidden behind forms
                try:
                    if method == "POST":
                        # Builds a base payload from inputs and text areas
                        dataBase = {}
                        for inp in form.find_all("input"):
                            name = (inp.get("name") or "").strip()

                            if not name:
                                continue

                            typ = (inp.get("type") or "").lower()
                            value = inp.get("value") or ""

                            # Only include "checkbox", "radio" if they are checked
                            if typ in ("checkbox", "radio"):
                                if inp.has_attr("checked"):
                                    dataBase[name] = value

                            else:
                                dataBase.setdefault(name, value)

                        # Capture the text
                        for textArea in form.find_all("textarea"):
                            name = (textArea.get("name") or "").strip()
                            if name:
                                dataBase.setdefault(name, textArea.text or "")

                        # Identify submits for first submit
                        submitButtons = [((button.get("name") or "").strip(), (button.get("value") or button.text or "Submit").strip())
                            for button in form.find_all(["input", "button"])
                            if (button.get("type") or "").lower() in ("submit", "image", "button", "") and (button.get("name") or "").strip() ]

                        # Collect select values up to option capacity
                        optionCap = int(cfg["crawler"]["option_capacity"])

                        selects = {(select.get("name") or "").strip():
                            [(option.get("value") or option.text or "").strip() for option in select.find_all("option")if (option.get("value") or option.text or "").strip()]
                            [:optionCap]
                            for select in form.find_all("select") if (select.get("name") or "").strip()}

                        # Build candidate payloads
                        candidatePayloads = [dict(dataBase)]

                        for selectName, values in selects.items():
                            for val in values:
                                payload = dict(dataBase)
                                payload[selectName] = val
                                candidatePayloads.append(payload)

                        # send payload once record then send new form
                        for payload in candidatePayloads:
                            if submitButtons:
                                sbn, sbv = submitButtons[0]
                                payload.setdefault(sbn, sbv)

                            try:
                                res = self.session.post(actionUrl, data=payload, allow_redirects=True, timeout=cfg["http"]["crawl_post"])

                            except Exception:
                                log.debug("Submitting form via POST failed: %s", actionUrl, exc_info=True)
                                continue

                            # If not 200 OK then continue
                            if res.status_code != 200:
                                continue

                            if self.rateLimit:
                                time.sleep(self.rateLimit)

                            payload = urlparse(res.url or "")

                            # If not linked outside domain record and not visited record and queue
                            if payload.netloc == domain:
                                if res.url and res.url not in visited:
                                    visited.add(res.url)
                                    queue.append(res.url)

                                    endpointPath = (payload.path or "/") + (("#" + payload.fragment) if payload.fragment else "")
                                    staticEndpoints.add((endpointPath, "GET", tuple(parse_qs(payload.query).keys())))

                            # Parse forms in response
                            psoup = BeautifulSoup(res.text or "", "html.parser")

                            for form2 in psoup.find_all("form"):
                                action2 = form2.get("action", "") or res.url
                                method2 = (form2.get("method", "GET") or "GET").upper()
                                abs2 = urljoin(res.url, action2)
                                parse2 = urlparse(abs2)

                                # If not part of domain skip
                                if parse2.netloc and parse2.netloc != domain:
                                    continue

                                formPath2 = f"{parse2.scheme}://{parse2.netloc}{parse2.path or '/'}"
                                if parse2.fragment:
                                    formPath2 += "#" + parse2.fragment

                                # Collect new forms inputs and record
                                fields2 = []
                                for input2 in form2.find_all(["input", "textarea", "select"]):
                                    name2 = (input2.get("name") or input2.get("id") or input2.get("placeholder") or "").strip()
                                    if name2:
                                        fields2.append(name2)
                                staticForms.append({"url": formPath2, "method": method2, "formFields": fields2})

                except Exception:
                    log.debug("Static crawl parsing failed on %s", currentUrl, exc_info=True)
                    pass

            pagesCrawled += 1

        # Convert set of tuples to list of dics
        endpointDicts = []
        for path, method, params in staticEndpoints:
            endpointDicts.append({
                "url": path,
                "method": method,
                "params": list(params)
            })

        return endpointDicts, staticForms


    def crawlDynamic(self, startUrl, domain):
        """
            Dynamic crawl uses Selenium to handle javascript content
            return endpointDicts, dynamicForms
        """

        # Sets up selenium webdriver
        options = Options()
        if self.headless:
            options.headless = True
            options.add_argument("--headless=new")
        options.add_argument("--window-size=1920,1080")

        # TO silence console
        options.add_argument("--log-level=3")
        options.add_experimental_option("excludeSwitches", ["enable-logging"])

        self.driver = webdriver.Chrome(options=options)
        driver = self.driver

        # Selenium login
        if self.auth and self.loginUsername and self.loginPassword:

            ok = seleniumLogin(
                driver,
                baseUrl=startUrl,
                username=self.loginUsername,
                password=self.loginPassword,
                loginPath=self.loginPath
            )
            if not ok:
                status("[!] Selenium login failed"); log.warning("Selenium login failed")
            else:
                # Copies cookies into Cookie Jar
                jar = RequestsCookieJar()

                for c in self.driver.get_cookies():
                    try:
                        jar.set(name=c.get("name"), value=c.get("value"),
                                domain=c.get("domain"), path=c.get("path") or "/")

                    except Exception:
                        jar.set(c.get("name"), c.get("value"))

                self.session.cookies.update(jar)

        visited = set()
        queue = [startUrl]

        dynamicEndpoints = set()
        dynamicForms = []
        pagesLoaded = 0

        try:
            while queue and (not self.maxPages or pagesLoaded < self.maxPages):
                # Get next URL from queue
                url = queue.pop(0)
                if url in visited:
                    continue

                visited.add(url)
                driver.get(url)

                # If there's a collapsible menu try to open it
                try:
                    menuButton = driver.find_element(By.CSS_SELECTOR, "[aria-label='Open Menu'], .burger")
                    menuButton.click()
                    # wait for menu to expand
                    WebDriverWait(driver, 0.5).until(expected_conditions.presence_of_element_located((By.TAG_NAME, "body")))
                except Exception:
                    log.debug("Menu expand click failed", exc_info=True)
                    # no menu found or click failed
                    pass

                # Extract links
                links = driver.find_elements(By.TAG_NAME, "a")

                for l in links:
                    href = l.get_attribute("href")

                    if not href or href.startswith("javascript:") or href.startswith("mailto:"):
                        continue

                    # Make URL absolute
                    absHref = urljoin(driver.current_url, href)

                    # Stay within the same domain
                    parsed = urlparse(absHref)
                    if parsed.netloc != domain:
                        continue

                    # Add link to queue if not visited
                    if absHref not in visited and absHref not in queue:
                        queue.append(absHref)

                    # Add endpoint
                    endpointPath = parsed.path or "/"
                    if parsed.fragment:
                        endpointPath += "#" + parsed.fragment
                    params = list(parse_qs(parsed.query).keys())
                    dynamicEndpoints.add((endpointPath, "GET", tuple(params)))

                # Handle pages where fields are not inside <form> tags
                seenForms = set()

                allInputs = driver.find_elements(By.TAG_NAME, "input")
                allTextareas = driver.find_elements(By.TAG_NAME, "textarea")
                allSelects = driver.find_elements(By.TAG_NAME, "select")

                freeFields = []
                for el in (allInputs+ allTextareas + allSelects):
                    try:
                        el.find_element(By.XPATH, "ancestor::form")

                    except Exception:
                        identifier = extractIdentifier(el)
                        if identifier:
                            freeFields.append(identifier)

                if freeFields:
                    parsedCurrentUrl = urlparse(driver.current_url)
                    if parsedCurrentUrl.netloc and parsedCurrentUrl.netloc != domain:
                        continue
                    formPath = f"{parsedCurrentUrl.scheme}://{parsedCurrentUrl.netloc}{parsedCurrentUrl.path or '/'}"

                    if parsedCurrentUrl.fragment:
                        formPath += "#" + parsedCurrentUrl.fragment

                    key = (formPath, "POST")

                    if key not in seenForms:
                        dynamicForms.append({
                            "url": formPath,
                            "method": "POST",
                            "formFields": list(set(freeFields))
                        })

                        seenForms.add(key)

                # Collect all real <form>
                forms = driver.find_elements(By.TAG_NAME, "form")

                for f in forms:
                    action = f.get_attribute("action") or url
                    method = f.get_attribute("method") or "GET"
                    inputs = f.find_elements(By.TAG_NAME, "input")
                    textareas = f.find_elements(By.TAG_NAME, "textarea")
                    selects = f.find_elements(By.TAG_NAME, "select")

                    fields = []
                    for el in (inputs + textareas + selects):
                        identifier = extractIdentifier(el)
                        if identifier:
                            fields.append(identifier)

                    base = driver.current_url
                    formUrl = urljoin(base, action or base)
                    parsedForm = urlparse(formUrl)

                    if parsedForm.netloc and parsedForm.netloc != domain:
                        continue

                    formPath = f"{parsedForm.scheme}://{parsedForm.netloc}{parsedForm.path or '/'}"
                    if parsedForm.fragment:
                        formPath += "#" + parsedForm.fragment

                    key = (formPath, method.upper())
                    if key not in seenForms:
                        dynamicForms.append({
                            "url": formPath,
                            "method": method.upper(),
                            "formFields": fields
                        })
                        seenForms.add(key)

                pagesLoaded +=1

                if self.rateLimit:
                    time.sleep(self.rateLimit)

        finally:
            driver.quit()

        # Convert set of tuples to list of dics
        endpointDicts = []
        for path, method, params in dynamicEndpoints:
            endpointDicts.append({
                "url": path,
                "method": method,
                "params": list(params)
            })

        return endpointDicts, dynamicForms
