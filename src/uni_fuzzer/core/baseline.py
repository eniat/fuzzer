
from uni_fuzzer.core.utility import get_cfg

cfg = get_cfg()

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