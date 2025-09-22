import re
import logging
from difflib import SequenceMatcher
from urllib.parse import quote, unquote_plus
from html import escape, unescape

from uni_fuzzer.core.utility import get_cfg

cfg = get_cfg()
log = logging.getLogger(__name__)

# Regex templates for XSS injections
SCRIPT_RE = cfg["xss"]["regex"]["script"]
ATTR_RE = cfg["xss"]["regex"]["attr"]
JSURL_RE = cfg["xss"]["regex"]["jsurl"]
RAW_HTML_RE = cfg["xss"]["regex"]["raw_html"]
HTML_COMMENT_RE = cfg["xss"]["regex"]["html_comment"]
JS_STRINGS   = re.compile(r"""(['"])(?:\\.|(?!\1).)*\1""", re.S)
JS_LINECOM   = re.compile(r"//[^\n\r]*")
JS_BLOCKCOM  = re.compile(r"/\*.*?\*/", re.S)
SCRIPT_BLOCK = re.compile(r"<script[^>]*>(.*?)</script>", re.I | re.S)
# Cache for regex objects to avoid recompiling
_REGEX_CACHE = {}

# To exclude SQL errors when looking for XSS
SQL = cfg["sqli"]["error_signatures"]

# SQL Detection
TIMING_THRESHOLD_MS = cfg["sqli"]["timing_threshold_ms"]
BLIND_FACTOR  = cfg["sqli"]["blind_timing_factor"]
BOOLEAN_SUCCESS_KEYWORDS = cfg["sqli"]["boolean_success_keywords"]
BOOLEAN_FAILURE_KEYWORDS = cfg["sqli"]["boolean_failure_keywords"]

def detectXSS(body, token, markedPayload):
    """
        If token appears then it's worked
    """
    lowerBody = (body or "").lower()
    token = (token or "").lower()
    lowerBodyQ = unquote_plus(body).lower()
    lowerBodyU = unescape(body or "").lower()

    if token not in lowerBody and token not in lowerBodyU and token not in lowerBodyQ:
        return False, None

    # cache regex for this token
    if token not in _REGEX_CACHE:

        if len(_REGEX_CACHE) >= 32:
            _REGEX_CACHE.clear()

        _REGEX_CACHE[token] = (
            re.compile(SCRIPT_RE.format(token=re.escape(token)), re.I | re.S),
            re.compile(ATTR_RE.format(token=re.escape(token)), re.I | re.S),
            re.compile(JSURL_RE.format(token=re.escape(token)), re.I | re.S),
            re.compile(RAW_HTML_RE.format(token=re.escape(token)), re.I | re.S),
            re.compile(HTML_COMMENT_RE.format(token=re.escape(token)), re.I | re.S)
        )

    script_re, attr_re, jsurl_re, raw_re, cmt_re = _REGEX_CACHE[token]

    # Filter SQL errors
    if any(err.lower() in lowerBody for err in SQL) or any(err.lower() in lowerBodyU for err in SQL):
        return False, None

    # Check if token survives removal of strings ect
    if script_re.search(lowerBodyU):
        for blk in SCRIPT_BLOCK.findall(lowerBodyU):
            cleaned = JS_BLOCKCOM.sub("", blk)
            cleaned = JS_LINECOM.sub("", cleaned)
            cleaned = JS_STRINGS.sub("", cleaned)
            if token in cleaned.lower():
                log.debug("XSS detected: script_ctx (token=%s)", token)
                return True, "script_ctx"

    # fallback
    if script_re.search(lowerBody):
        for blk in SCRIPT_BLOCK.findall(lowerBody):
            cleaned = JS_BLOCKCOM.sub("", blk)
            cleaned = JS_LINECOM.sub("", cleaned)
            cleaned = JS_STRINGS.sub("", cleaned)
            if token in cleaned.lower():
                return True, "script_ctx"

    # Checks if canary is inside JS String
    canaryJs = re.compile(r'(?:^|[^a-z0-9_])(?:window\.)?__xss_canary__\s*[:=]\s*["\']?\s*' + re.escape(token) + r'\s*["\']?',re.I)
    if canaryJs.search(lowerBodyU) or canaryJs.search(lowerBody):
        log.debug("XSS detected: script_ctx (token=%s)", token)
        return True, "script_ctx"

    # Check if xss is in dangerous contexts
    if attr_re.search(lowerBodyU) or jsurl_re.search(lowerBodyU):
        log.debug("XSS detected: attr_ctx (token=%s)", token)
        return True, "attr_ctx"
    if attr_re.search(lowerBody) or jsurl_re.search(lowerBody):
        log.debug("XSS detected: attr_ctx (token=%s)", token)
        return True, "attr_ctx"
    if raw_re.search(body) or raw_re.search(lowerBodyU) or raw_re.search(lowerBodyQ) or \
            cmt_re.search(body) or cmt_re.search(lowerBodyU) or cmt_re.search(lowerBodyQ):
        log.debug("XSS detected: raw_html_ctx (token=%s)", token)
        return True, "raw_html_ctx"

    # Checks if canary is near inline handler like onmouseover
    canaryNear = re.compile(r'on[a-z]+\s*=\s*[^>]{0,200}' + re.escape(token), re.I | re.S)
    if canaryNear.search(lowerBodyU) or canaryNear.search(lowerBody):
        log.debug("XSS detected: attr_ctx (token=%s)", token)
        return True, "attr_ctx"

    if markedPayload:
        mp = str(markedPayload)
        mpHtml = escape(mp, quote=True).lower()
        mpUrl = quote(mp, safe="").lower()
        mpUrlp = quote(mp, safe="").replace("%20", "+").lower()

        if (mpHtml and (mpHtml in lowerBody or mpHtml in lowerBodyU)) or \
                (mpUrl and (mpUrl in lowerBody or mpUrl in lowerBodyU or mpUrl in lowerBodyQ)) or \
                (mpUrlp and (mpUrlp in lowerBody or mpUrlp in lowerBodyU or mpUrlp in lowerBodyQ)):
            log.debug("XSS detected: raw_html_ctx (token=%s)", token)
            return True, "raw_html_ctx"

    return False, None

def detectSQLError(body):
    """
        Detects SQL errors which highlights potential vulnerabilities
    """
    lower = (body or "").lower()

    for err in SQL:
        if err in lower:
            log.debug("SQL error signature matched: %s", err)
            return True, err

    return False, None

def detectSQLiBlind(baseMs, testMs, thresholdMs= TIMING_THRESHOLD_MS, factor=BLIND_FACTOR):
    """
        Detects SQLi blind by checking timing difference
    """
    ok = (testMs >= baseMs * factor) and ((testMs - baseMs) >= thresholdMs)
    if ok:
        log.debug("SQLi blind: base=%.1fms test=%.1fms factor=%.2f thr=%dms", baseMs, testMs, factor, thresholdMs)
    return ok

def detectSQLiDiff(baseHtml, html, isNotSQLIBlind=True, true= None, false=None, payload=None):
    """
        Detect SQLi content by comparing the basehtml with the html after and assessing differences/
        Detect blind SQLi by checking two word lists
    """
    b = (baseHtml or "").lower()
    h = (html or "").lower()

    if not isNotSQLIBlind:
        # Check if payloads are reflected
        if (true and true.lower() in h) or (true and true.lower() in b):
            return False
        if (false and false.lower() in h) or (false and false.lower() in b):
            return False

        hasSuccB = any(s in b for s in BOOLEAN_SUCCESS_KEYWORDS)
        hasFailB = any(f in b for f in BOOLEAN_FAILURE_KEYWORDS)
        hasSuccH = any(s in h for s in BOOLEAN_SUCCESS_KEYWORDS)
        hasFailH = any(f in h for f in BOOLEAN_FAILURE_KEYWORDS)

        # True page shows success whilst other shows fail or opposite
        if (hasSuccB and hasFailH) or (hasFailB and hasSuccH):
            log.debug("SQLi boolean content: success/fail divergence detected")
            return True

        return False

    if isNotSQLIBlind:
        esc = escape(str(payload or ""), quote=True).lower()
        if esc and (esc in h or esc in b):
            return False

    if re.search(r"user id (exists|is missing) in the database", h, flags=re.I) \
            and not re.search(r"user id (exists|is missing) in the database", b, flags=re.I):
        return False

    preB, preH = b.count("<pre"), h.count("<pre")
    trB, trH = b.count("<tr"), h.count("<tr")
    tdB, tdH = b.count("<td"), h.count("<td")

    Pres = (preH - preB) >= 2
    Tabs = (trH - trB) >= 2 and (tdH - tdB) >= 2

    if Pres or Tabs:

        if Pres:
            log.debug("SQLi content: <pre> block count increased")
            return True

        if (trH > trB) and (tdH > tdB):
            log.debug("SQLi content: table row/col count increased")
            return True

    delta = abs(len(h) - len(b))
    if delta >= int(cfg["sqli"]["confirm_min_size_delta"]):
        log.debug("SQLi content: size delta %d >= threshold", delta)
        return True

    return False

def detectPathTraversal(response, baseline=None, similarity_skip_threshold=cfg["fuzz"]["similarity_skip_threshold"]):
    """
        Detect success based on response
    """
    # Below set in config/defaults.yaml
    indicators = cfg["path_traversal"]["indicators"]
    content = response.text.lower()
    status = response.status_code

    # Check for indicators in response
    for indicator in indicators:
        if re.search(rf'\b{re.escape(indicator)}\b', content):
            log.debug("Path traversal indicator matched: %s", indicator)
            return "vulnerable", indicator

    # if status is 200 baseline check
    if status == 200:
        if baseline:

            baselineT = baseline.get("content", "")
            baselineS = baseline.get("status_code")
            similarity = SequenceMatcher(None, baselineT, response.text or "").quick_ratio()

            # Skip if similar to baseline
            if status == baselineS and similarity >= similarity_skip_threshold:
                log.debug("Path traversal skipped by similarity: %.3f", similarity)
                return "skip_similar", similarity

            log.debug("Path traversal interesting (status=%s, similarity=%.3f)", status, similarity if baseline else -1.0)
            # If not mark interesting
            return "interesting_200", similarity
        return "interesting", None
    return "none", None