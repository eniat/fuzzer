import requests

from urllib.parse import urljoin,urlparse
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.wait import WebDriverWait
from bs4 import BeautifulSoup

from uni_fuzzer.core.utility import get_cfg
cfg = get_cfg()

def seleniumLogin(driver, baseUrl, username, password, loginPath=None, selectors=None):
    """
        Log in to webapp using Selenium
    """

    try:
        # Retrieves defaults from yaml
        sel = {
            "username_field": cfg["auth"]["selectors"]["username_field"],
            "password_field": cfg["auth"]["selectors"]["password_field"],
            "submit_name": cfg["auth"]["selectors"]["submit_name"],
        }

        if selectors:
            sel.update({k: v for k, v in selectors.items() if v})

        waits = cfg["auth"]["selenium_wait_seconds"]

        # Sets login URL
        lp = loginPath or cfg["auth"]["login_path"]
        loginUrl = lp if lp.startswith("http") else urljoin(baseUrl, lp)

        # Opens login page
        driver.get(loginUrl)

        # Waits for page to load then enters either defaults or given username
        WebDriverWait(driver, waits["short"]).until(expected_conditions.presence_of_element_located((By.NAME, sel["username_field"])) )
        driver.find_element(By.NAME, sel["username_field"]).clear()
        driver.find_element(By.NAME, sel["username_field"]).send_keys(username)

        # Waits for page to load then enters either defaults or given password
        WebDriverWait(driver, waits["short"]).until(expected_conditions.presence_of_element_located((By.NAME, sel["password_field"])))
        driver.find_element(By.NAME, sel["password_field"]).clear()
        driver.find_element(By.NAME, sel["password_field"]).send_keys(password)

        # Submits form
        driver.find_element(By.NAME, sel["submit_name"]).click()

        # Success based on URL changing or login disappearing
        WebDriverWait(driver, waits["medium"]).until(
            lambda d: (
                    expected_conditions.invisibility_of_element_located((By.NAME, sel["username_field"]))(d)
                    or d.current_url != loginUrl
                    or ("login" not in d.current_url.lower())
            )
        )

        return True

    except Exception as e:
        print(f"[!] Selenium login failed: {e}")
        return False

def login(session, baseUrl, username, password, loginPath=None, selectors=None, headers=None):
    """
        Log in to webapp using default credentials and set security to low
    """

    try:
        # Retrieves defaults from yaml
        sel = {
            "username_field": cfg["auth"]["selectors"]["username_field"],
            "password_field": cfg["auth"]["selectors"]["password_field"],
            "submit_name": cfg["auth"]["selectors"]["submit_name"],
        }

        if selectors:
            sel.update({k: v for k, v in selectors.items() if v})

        # Sets login URL
        lp = loginPath or cfg["auth"]["login_path"]
        loginUrl = lp if lp.startswith(("http://", "https://")) else urljoin(baseUrl, lp)

        reqHeaders = {
            "User-Agent": cfg["http"]["user_agent"],
            "Referer": loginUrl,
        }

        if headers:
            reqHeaders.update(headers)

        res = session.get(loginUrl, headers=reqHeaders, timeout=cfg["http"]["timeout_get_seconds"])
        if res.status_code >= 400:
            return False

        soup = BeautifulSoup(res.text, "html.parser")

        # pick first form on the page, if not post to loginURL
        form = soup.find("form")
        postUrl = loginUrl

        if form:
            action = form.get("action")

            if action and not action.startswith("javascript:"):
                postUrl = urljoin(loginUrl, action)

        data = {}

        if form:
            for inp in form.find_all("input"):
                name = inp.get("name")

                if not name:
                    continue

                itype = (inp.get("type") or "").lower()

                if itype in ("hidden", "submit"):
                    data[name] = inp.get("value", "")

        data[sel["username_field"]] = username
        data[sel["password_field"]] = password

        data.setdefault(sel["submit_name"], "Login")

        pr = session.post(postUrl, data=data, headers=reqHeaders,timeout=cfg["http"]["timeout_post_seconds"], allow_redirects=False)

        if 300 <= pr.status_code < 400:
            return True


        gr = session.get(loginUrl, headers=reqHeaders, timeout=cfg["http"]["timeout_get_seconds"])
        if gr.status_code >= 400:
            return True

        gs = BeautifulSoup(gr.text, "html.parser")
        stillLogin = gs.find(attrs={"name": sel["username_field"]}) is not None
        if not stillLogin:
            return True

        lpPath = urlparse(loginUrl).path or "/"
        curPath = urlparse(gr.url).path or "/"
        return lpPath != curPath

    except requests.RequestException:
        return False
    except Exception:
        return False