import time
import logging

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from urllib.parse import urljoin, urlparse, parse_qs, urldefrag
from requests.cookies import RequestsCookieJar

from ..core.base_crawler import BaseCrawler
from ..core.utility import get_cfg

cfg = get_cfg()
log = logging.getLogger(__name__)

class DynamicCrawler(BaseCrawler):
    name = "dynamic"

    def run(self, startUrl, ctx = None):
        """
            Dynamic crawl uses Selenium to handle javascript content
            return endpointDicts, dynamicForms
        """

        endpointsMap: dict[tuple[str, str], set[str]] = {}
        formsMap: dict[tuple[str, str], set[str]] = {}

        # Extract domain from start
        domain = urlparse(startUrl).netloc

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

        # Selenium login
        if self.auth and self.loginUsername and self.loginPassword:

            ok = self.ctx.auth.selenium_login(
                driver,
                base_url=startUrl,
                username=self.loginUsername,
                password=self.loginPassword,
                login_path=self.loginPath
            )
            if not ok:
                self.ctx.util.status("[!] Selenium login failed")
                log.warning("Selenium login failed")
            else:
                # Copies cookies into Cookie Jar
                jar = RequestsCookieJar()

                for c in driver.get_cookies():
                    try:
                        jar.set(name=c.get("name"), value=c.get("value"),
                                domain=c.get("domain"), path=c.get("path") or "/")

                    except Exception:
                        jar.set(c.get("name"), c.get("value"))

                self.session.cookies.update(jar)

        visited: set[str] = set()
        queue = [urldefrag(startUrl)[0]]
        pagesLoaded = 0

        try:
            while queue and (not self.maxPages or pagesLoaded < self.maxPages):
                # Get next URL from queue
                url = queue.pop(0)
                urlN = urldefrag(url)[0]
                if urlN in visited:
                    continue

                visited.add(urlN)
                driver.get(urlN)

                WebDriverWait(driver, cfg["crawler"]["dom_wait"]).until(expected_conditions.presence_of_element_located((By.TAG_NAME, "body")))

                # Extract links
                for a in driver.find_elements(By.TAG_NAME, "a"):
                    href = (a.get_attribute("href") or "").strip()
                    if not href or href.startswith(("javascript:", "mailto:")):
                        continue

                    # Make URL absolute
                    absHref = urljoin(driver.current_url, href)
                    absHrefN = urldefrag(absHref)[0]

                    # Stay within the same domain
                    parsed = urlparse(absHrefN)
                    if parsed.netloc != domain:
                        continue

                    # Add link to queue if not visited
                    if absHrefN not in visited and absHrefN not in queue:
                        queue.append(absHrefN)

                    # Add endpoint
                    endpointPath = parsed.path or "/"
                    if parsed.fragment:
                        endpointPath += "#" + parsed.fragment
                    params = list(parse_qs(parsed.query).keys())
                    endpointsMap.setdefault((endpointPath, "GET"), set()).update(params)

                # Handle pages where fields are not inside <form> tags
                freeFields = []
                for tag in ("input", "textarea", "select"):
                    for el in driver.find_elements(By.TAG_NAME, tag):
                        try:
                            el.find_element(By.XPATH, "ancestor::form")
                        except Exception:
                            identifier = self.ctx.util.extract_identifier(el)
                            if identifier:
                                freeFields.append(identifier)

                if freeFields:
                    parsedCurrentUrl = urlparse(driver.current_url)
                    if parsedCurrentUrl.netloc and parsedCurrentUrl.netloc != domain:
                        continue
                    formPath = f"{parsedCurrentUrl.scheme}://{parsedCurrentUrl.netloc}{parsedCurrentUrl.path or '/'}"

                    if parsedCurrentUrl.fragment:
                        formPath += "#" + parsedCurrentUrl.fragment
                    formsMap.setdefault((formPath, "POST"), set()).update(freeFields)

                # Collect all real <form>
                for form in driver.find_elements(By.TAG_NAME, "form"):
                    action = (form.get_attribute("action") or driver.current_url).strip()
                    method = (form.get_attribute("method") or "GET").upper()
                    absAction = urljoin(driver.current_url, action)

                    pa = urlparse(absAction)

                    if pa.netloc != domain:
                        continue

                    fpath = f"{pa.scheme}://{pa.netloc}{pa.path or '/'}"

                    if pa.fragment:
                        fpath += f"#{pa.fragment}"

                    fields = []
                    for tag in ("input", "textarea", "select"):
                        for el in form.find_elements(By.TAG_NAME, tag):
                            identifier = self.ctx.util.extract_identifier(el)
                            if identifier:
                                fields.append(identifier)

                    formsMap.setdefault((fpath, method), set()).update(fields)

                pagesLoaded += 1

                if self.rateLimit:
                    time.sleep(self.rateLimit)


        finally:
            try:
                driver.quit()
            except Exception:
                log.debug("driver.quit() failed", exc_info=True)

            # Convert set of tuples
            endpointDicts = [
                {"url": path, "method": method, "params": sorted(list(params))}
                for (path, method), params in endpointsMap.items()
            ]
            formsList = [
                {"url": path, "method": method, "formFields": sorted(list(fields))}
                for (path, method), fields in formsMap.items()
            ]

            return endpointDicts, formsList
