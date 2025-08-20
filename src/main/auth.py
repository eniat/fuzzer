from urllib.parse import urljoin
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.wait import WebDriverWait


def seleniumLogin(driver, baseUrl):
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

        return True

    except Exception as e:
        print(f"[!] Selenium login failed: {e}")
        return False