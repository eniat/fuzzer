import requests
import time
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urldefrag
import re

class Crawler:

    def __init__(self, mode='both', maxPages= 5, rateLimit=0.0, headless= True, outputToFile=False, isDVWA= False):
        # Crawler settings
        self.mode = mode
        self.maxPages = maxPages if maxPages is not None else 0
        self.rateLimit = rateLimit
        self.headless = headless
        self.outputToFile = outputToFile

        # Storage for results
        self.discoveredEndpoints = []
        self.discoveredForms = []

        # FOR dvwa
        self.isDVWA = isDVWA
        self.session = requests.Session() if isDVWA else None

    def crawl (self, startUrl):
        """
        Crawl from starting url using the set mode, either static or dynamic
        return self.discoveredEndpoints, self.discoveredForms
        """

        if self.isDVWA:
            loggedIn = self.login(startUrl)
            if not loggedIn:
                print("[!] DVWA Login failed!")
                return [], []

        self.discoveredEndpoints = []
        self.discoveredForms = []
        endpointsMap = {}
        formsMap = {}

        # Extract domain from start
        domain = urlparse(startUrl).netloc

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

        # If 'outputToFile=True' creates a file listing the output, For debugging
        if self.outputToFile:
            with open("crawlerOutput.txt", "w") as f:
                f.write("Discovered Endpoints:\n")
                for ep in self.discoveredEndpoints:
                    f.write(f"{ep['method']} {ep['url']} params={ep['params']}\n")
                f.write("\n Discovered Forms:\n ")
                for fm in self.discoveredForms:
                    f.write(f"{fm['method']} {fm['url']} fields={fm['formFields']}\n")

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
                response = self.session.get(currentUrl) if self.isDVWA else requests.get(currentUrl)
            except requests.RequestException as e:
                # On error requesting notify
                print (f"Request Failed: {e}")
                continue
            if response.status_code != 200:
                #Skips non OK pages
                continue

            if self.rateLimit:
                time.sleep(self.rateLimit)

            # Only parse HTML
            contentType = response.headers.get("Content-Type", "")
            if "text/html" not in contentType:
                pagesCrawled += 1
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

                formPath = parsedAction.path or "/"
                if parsedAction.fragment:
                    formPath += "#" + parsedAction.fragment

                # Get clean identifiers
                fields = []
                for inp in form.find_all(['input', 'textarea', 'select']):
                    identifier = self.extractIdentifier(inp)
                    if identifier:
                        fields.append(identifier)

                # Get all input fields
                staticForms.append({"url": formPath, "method": method, "formFields": fields})
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

        driver = webdriver.Chrome(options=options)

        baseUrl = f"{urlparse(startUrl).scheme}://{urlparse(startUrl).netloc}"
        if self.isDVWA:
            loggedIn = self.seleniumLogin(driver, baseUrl)
            if not loggedIn:
                print("[!] Selenium login failed. Aborting dynamic crawl.")
                driver.quit()
                return [], []

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
                    # no menu found or click failed
                    pass

                # Extract links
                links = driver.find_elements(By.TAG_NAME, "a")

                for l in links:
                    href = l.get_attribute("href")

                    if not href or href.startswith("javascript:") or href.startswith("mailto:"):
                        continue

                    # Make URL absolute
                    absHref = urljoin(url, href)
                    absHref = urldefrag(absHref)[0] if "#" not in absHref else absHref

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
                parsedCurrentUrl = urlparse(driver.current_url)
                formPath = parsedCurrentUrl.path or "/"
                if parsedCurrentUrl.fragment:
                    formPath += "#" + parsedCurrentUrl.fragment

                inputs = driver.find_elements(By.TAG_NAME, "input")
                textareas = driver.find_elements(By.TAG_NAME, "textarea")
                selects = driver.find_elements(By.TAG_NAME, "select")

                fields = []
                for el in (inputs + textareas + selects):
                    identifier = self.extractIdentifier(el)
                    if identifier:
                        fields.append(identifier)

                if fields:
                    dynamicForms.append({
                        "url": formPath,
                        "method": "POST",
                        # remove duplicates
                        "formFields": list(set(fields))
                    })

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
                        identifier = self.extractIdentifier(el)
                        if identifier:
                            fields.append(identifier)

                    formUrl = urljoin(url, action)
                    parsedForm = urlparse(formUrl)
                    formPath = parsedForm.path or "/"
                    if parsedForm.fragment:
                        formPath += "#" + parsedForm.fragment

                    dynamicForms.append({
                        "url": formPath,
                        "method": method.upper(),
                        "formFields": fields
                    })
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

    def extractIdentifier(self, el):
        """
            Extract identifier finds and filters identifiers for input fields
            -- Can be edited depending on what to filter/ find
            return identifier
        """

        # Selenium
        if hasattr(el, "get_attribute")and callable(getattr(el, "get_attribute", None)):
            raw = (
                    el.get_attribute("name") or
                    el.get_attribute("formcontrolname") or
                    el.get_attribute("id") or
                    el.get_attribute("aria-label") or
                    el.get_attribute("placeholder")
            )
        # beautiful soup
        else:
            raw = (
                    el.get("name") or
                    el.get("formcontrolname") or
                    el.get("id") or
                    el.get("aria-label") or
                    el.get("placeholder")
            )

        if not raw:
            return None

        normalized = raw.lower()

        junkKeywords = [
            "mat-", "mdc-", "cdk-", "ng-",
            "slider", "toggle", "checkbox",
            "submit", "reset", "button",
            "unnamed", "go to file", "input:"
        ]

        if any(junk in normalized for junk in junkKeywords):
            return None

        if len(normalized.strip()) < 3:
            return None

        return raw.strip()

    def login(self, startUrl):
        """
            Log in to DVWA using default credentials and set security to low
        """

        parsed = urlparse(startUrl)
        base = f"{parsed.scheme}://{parsed.netloc}"

        loginUrl = f"{base}/login.php"
        securityUrl = f"{base}/security.php"

        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
                "Referer": base,
            }

            loginPage = self.session.get(loginUrl, headers=headers)
            # print("[DEBUG] Login page response\n:", loginPage.text)

            tokenMatch = re.search(r'name=[\'"]user_token[\'"]\s*value=[\'"]([^\'"]+)[\'"]', loginPage.text)

            token = tokenMatch.group(1) if tokenMatch else ''
            # print(f"[DEBUG] CSRF token from login page:{token}")

            if not token:
                print("[!] Could not extract CSRF token from login page!")

                return False

            loginData = {
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": token
            }

            res = self.session.post(loginUrl, data=loginData,headers=headers)

            if "Login failed" in res.text:
                print("[!] Login failed. Check credentials.")
                return False

            securityPage = self.session.get(securityUrl, headers= headers)
            tokenMatch = re.search(r'name=[\'"]user_token[\'"]\s*value=[\'"]([^\'"]+)[\'"]', securityPage.text)
            token = tokenMatch.group(1) if tokenMatch else ''

            securityData = {
                "security": "low",
                "seclev_submit": "Submit",
                "user_token": token
            }

            self.session.post(securityUrl, data=securityData, headers= headers)
            # print("[+] Logged in to DVWA and set security level to low")

            return True

        except requests.RequestException as e:
            print(f"[!] Login request failed: {e}")
            return False

    def seleniumLogin(self, driver, baseUrl):
        """
            Log in to DVWA using Selenium
        """

        loginUrl = urljoin(baseUrl, "/login.php")
        driver.get(loginUrl)

        try:
            # Wait until login form loads
            WebDriverWait(driver, 1).until(expected_conditions.presence_of_element_located((By.NAME, "username")))

            driver.find_element(By.NAME, "username").send_keys("admin")
            driver.find_element(By.NAME, "password").send_keys("password")

            # Submit form
            driver.find_element(By.NAME, "Login").click()

            WebDriverWait(driver, 2).until(expected_conditions.url_contains("index.php"))

            # Go to security page and set to low
            driver.get(urljoin(baseUrl, "/security.php"))
            WebDriverWait(driver, 5).until(expected_conditions.presence_of_element_located((By.NAME, "security")))

            dropdown = driver.find_element(By.NAME, "security")
            for option in dropdown.find_elements(By.TAG_NAME, "option"):
                if option.get_attribute("value") == "low":
                    option.click()

            driver.find_element(By.NAME, "seclev_submit").click()
            # print("[+] Logged in to DVWA via Selenium and set security to low")

            return True

        except Exception as e:
            print(f"[!] Selenium login failed: {e}")
            return False