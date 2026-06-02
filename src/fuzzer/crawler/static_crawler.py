import requests
import time
import logging

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urldefrag

from ..core.utility import get_cfg
from ..core.base_crawler import BaseCrawler

cfg = get_cfg()
log = logging.getLogger(__name__)

class StaticCrawler(BaseCrawler):
    name = "static"

    def run(self, startUrl, ctx= None):
        """
            Static crawl fetches pages with requests and parses HTML with BeautifulSoup
            return endpointDicts, staticForms
        """

        endpointsMap: dict[tuple[str, str], set[str]] = {}
        formsMap: dict[tuple[str, str], set[str]] = {}

        # Extract domain from start
        domain = urlparse(startUrl).netloc

        if self.auth and self.loginUsername and self.loginPassword:
            ok = self.ctx.auth.http_login(
                self.session,
                startUrl,
                self.loginUsername,
                self.loginPassword,
                self.loginPath
            )
            if not ok:
                self.ctx.util.status("[!] HTTP login failed")
                log.warning("HTTP login failed")

        queue = [startUrl]
        visited = {startUrl}
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
                            endpointsMap.setdefault((routePath, "GET"), set()).update(params)
                    continue

                # Convert URL to absolute
                absUrl = urljoin(currentUrl, href)

                # Make sure link is within the base domain and hasn't been visited
                absUrlC = urldefrag(absUrl)[0]
                if urlparse(absUrlC).netloc == domain and absUrlC not in visited:
                    visited.add(absUrlC)
                    queue.append(absUrlC)

                # Record endpoint and any query parameters
                parsed = urlparse(absUrl)
                params = list(parse_qs(parsed.query).keys()) if parsed.query else []
                endpointPath = parsed.path or "/"
                if parsed.fragment:
                    endpointPath += "#" + parsed.fragment
                endpointsMap.setdefault((endpointPath, "GET"), set()).update(params)

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
                endpointsMap.setdefault((endpointPath, "GET"), set()).update(params)

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
                    identifier = self.ctx.util.extract_identifier(inp)
                    if identifier:
                        fields.append(identifier)

                # Get all input fields
                formsMap.setdefault((formPath, method), set()).update(fields)

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

                                    endpointPath = (payload.path or "/") + (f"#{payload.fragment}" if payload.fragment else "")
                                    endpointsMap.setdefault((endpointPath, "GET"), set()).update(parse_qs(payload.query).keys())

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
                                formsMap.setdefault((formPath2, method2), set()).update(fields2)

                except Exception:
                    log.debug("Static crawl parsing failed on %s", currentUrl, exc_info=True)
                    pass

            pagesCrawled += 1

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