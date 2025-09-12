
from urllib.parse import urljoin

from uni_fuzzer.core.utility import get_cfg, autoSubmits

cfg = get_cfg()
TIMING_BASELINE_PROBES = cfg["sqli"]["timing_baseline_probes"]

def baselineForm(session, url, headers):
    """
        Fetch form to deduce summit buttons
    """
    try:
        res = session.get(
            url,
            headers=headers,
            timeout=cfg["http"]["timeout_get_seconds"],
            allow_redirects=cfg["http"]["redirects"]["baseline_get"],
        )
        return {"content": res.text or ""}

    except Exception:
        return {"content": ""}

def getBaseline(session, baseUrl, headers):
    """
        Help path fuzzing with false positives
    """
    testPath = cfg["fuzz"]["baseline_404_path"]
    testUrl = urljoin(baseUrl, testPath)

    try:
        res = session.get(testUrl, headers=headers, timeout=cfg["http"]["timeout_get_seconds"], allow_redirects=cfg["http"]["redirects"]["baseline_get"])
        return {
            "status_code": res.status_code,
            "content": res.text
        }
    except Exception:
        return {"content": ""}

def sqliBaseline( session, headers, endpoint, method, fields):
    """
        Get baseline to compare if SQLi worked
    """
    try:
        if method == "POST":
            baseData = {f: "1" for f in fields}

            res = session.post(
                endpoint,
                data=baseData,
                headers=headers,
                timeout=cfg["sqli"]["timeout_blind"],
                allow_redirects=cfg["http"]["redirects"]["baseline_post"]
            )

            baseText, baseStatus = res.text or "", res.status_code

        else:
            res = session.get(
                endpoint,
                headers=headers,
                timeout=cfg["sqli"]["timeout_blind"],
                allow_redirects=cfg["http"]["redirects"]["baseline_get"]
            )

            html = res.text or ""

            params = {f: "1" for f in fields}
            params = autoSubmits(html, params)

            res = session.get(
                endpoint,
                params=params,
                headers=headers,
                timeout=cfg["sqli"]["timeout_blind"],
                allow_redirects=cfg["http"]["redirects"]["baseline_get"]
            )

            baseText, baseStatus = res.text or "", res.status_code

        return baseText, baseStatus

    except Exception:
        return "",0

def getBlindBaseline(session, headers, endpoint, method, fields, probes=TIMING_BASELINE_PROBES):
    """
        Get time baseline for blind SQLi timing
    """
    try:
        elapses = []

        if method == "POST":
            res = session.post(
                endpoint,
                headers=headers,
                timeout=cfg["sqli"]["timeout_blind"],
                allow_redirects=cfg["http"]["redirects"]["baseline_post"]
            )

            html = res.text or ""

            baseData = {f: "1" for f in fields}
            baseData = autoSubmits(html, baseData)

            for _ in range(max(1, int(probes))):
                res = session.post(
                    endpoint,
                    data=baseData,
                    headers=headers,
                    timeout=cfg["sqli"]["timeout_blind"],
                    allow_redirects=cfg["http"]["redirects"]["baseline_post"]
                )
                elapses.append(res.elapsed.total_seconds() * 1000.0)


        else:
            res = session.get(
                endpoint,
                headers=headers,
                timeout=cfg["sqli"]["timeout_blind"],
                allow_redirects=cfg["http"]["redirects"]["baseline_get"]
            )

            html = res.text or ""

            params = {f: "1" for f in fields}
            params = autoSubmits(html, params)

            for _ in range(max(1, int(probes))):
                res = session.get(
                    endpoint,
                    params=params,
                    headers=headers,
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