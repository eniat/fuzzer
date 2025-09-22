import logging
from html import unescape
from urllib.parse import quote

from uni_fuzzer.core.utility import get_cfg
from uni_fuzzer.fuzzers.detection import detectSQLiDiff

cfg = get_cfg()
log = logging.getLogger(__name__)

def probeReactivity(session, url, method, fields, fuzzField, headers):
    """
        Tests form to see if it is reactionary to avoid irrelevant fuzzing
    """
    try:
        if not fields or not fuzzField:
            return False


        if method == "POST":
            # Build POST
            baseData = {f: "1" for f in fields}

            baseRes = session.post(url, data=baseData, headers=headers, timeout=cfg["http"]["timeout_post_seconds"],allow_redirects=cfg["http"]["redirects"]["submit"])
            baseBody = baseRes.text or ""
            baseStatus = baseRes.status_code

            # Flip the 1 to 2
            data = {f: ("2" if f in fuzzField else "1") for f in fields}

            res = session.post(url, data=data, headers=headers,timeout=cfg["http"]["timeout_post_seconds"],allow_redirects=cfg["http"]["redirects"]["submit"])
            body = res.text or ""
            status = res.status_code

        else:
            # Build GET
            baseParams = [f"{f}=1" for f in fields]
            sep = "&" if "?" in url else "?"
            baseUrl = f"{url}{sep}{'&'.join(baseParams)}"

            baseRes = session.get(baseUrl, headers=headers, timeout=cfg["http"]["timeout_get_seconds"], allow_redirects=cfg["http"]["redirects"]["fuzz_get"])
            baseBody = baseRes.text or ""
            baseStatus = baseRes.status_code

            # Flip the 1 to 2
            params = [f"{f}=2" if f in fuzzField else f"{f}=1" for f in fields]
            fullUrl = f"{url}{sep}{'&'.join(params)}"

            res = session.get(fullUrl,headers=headers,timeout=cfg["http"]["timeout_get_seconds"], allow_redirects=cfg["http"]["redirects"]["fuzz_get"])
            body = res.text or ""
            status = res.status_code

        # Decide if reactive
        if baseStatus != status:
            return True

        # Detect difference
        if detectSQLiDiff(baseBody, body, payload=None):
            return True

        # Check min change
        minDelta = int(cfg["sqli"]["plain_preprobe_min_delta"])

        if abs(len((body or "").strip()) - len((baseBody or "").strip())) >= minDelta:
            return True

    except Exception:
        log.debug("probeReactivity failed for %s %s", method, url, exc_info=True)
        pass

    return False

def probeDom(driver, tokenLow):
    """
        Check dom side effects of payloads
    """
    try:
        return driver.execute_script("""
        const L = s => (s||'').toLowerCase();
        const t = arguments[0];
        let gflag = '', ls = '', ss = '';
        try { gflag = L(window.__XSS_CANARY__); } catch(e){}
        try { ls = L(JSON.stringify(Object.values(localStorage))); } catch(e){}
        try { ss = L(JSON.stringify(Object.values(sessionStorage))); } catch(e){}
        let el = false;
        try { el = !!document.querySelector(`x-canary[data-t="${t}"]`); } catch(e){}
        return { gflag: gflag.includes(t), ls: ls.includes(t), ss: ss.includes(t), el };""", tokenLow) or {}

    except Exception:
        log.debug("probeDom JS execution failed", exc_info=True)
        return {}

def probeReflexivity(session, url,method, fields, fuzzField, headers, token):
    """
        Probe to check if reflected back for form fuzzing
    """
    probe = f"xssprobe-{token}"

    try:
        if method == "POST":
            data = {f: (probe if f in fuzzField else "test") for f in fields}
            res = session.post(url, data=data, headers=headers, timeout=cfg["http"]["timeout_get_seconds"],allow_redirects=cfg["http"]["redirects"]["submit"])

        else:
            params = [f"{f}={quote(probe, safe='')}" if f in fuzzField else f"{f}=test" for f in fields]
            separator = "&" if "?" in url else "?"
            fullUrl = f"{url}{separator}{'&'.join(params)}"

            res = session.get(fullUrl, headers=headers, timeout=cfg["http"]["timeout_get_seconds"], allow_redirects=cfg["http"]["redirects"]["fuzz_get"])

        body = res.text or ""
        low = body.lower()

        if probe.lower() in low or unescape(body).lower().find(probe.lower()) != -1:
            return True

    except Exception:
        log.debug("probeReflexivity failed for %s %s", method, url, exc_info=True)
        pass

    return False
