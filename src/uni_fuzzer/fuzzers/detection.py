import re
import logging
from difflib import SequenceMatcher
from urllib.parse import unquote_plus
from html import escape, unescape

from uni_fuzzer.core.utility import get_cfg

cfg = get_cfg()
log = logging.getLogger(__name__)

# Regex templates for XSS injections
JS_STRINGS   = re.compile(r"""(['"])(?:\\.|(?!\1).)*\1""", re.S)
JS_LINECOM   = re.compile(r"//[^\n\r]*")
JS_BLOCKCOM  = re.compile(r"/\*.*?\*/", re.S)
SCRIPT_BLOCK = re.compile(r"<script[^>]*>(.*?)</script>", re.I | re.S)

# To detect SQL errors
SQL = cfg["sqli"]["error_signatures"]

# SQL Blind Detection
TIMING_THRESHOLD_MS = cfg["sqli"]["timing_threshold_ms"]
BLIND_FACTOR  = cfg["sqli"]["blind_timing_factor"]
BOOLEAN_SUCCESS_KEYWORDS = cfg["sqli"]["boolean_success_keywords"]
BOOLEAN_FAILURE_KEYWORDS = cfg["sqli"]["boolean_failure_keywords"]

def detectXSS(body, token):
    """
        If token appears then it's worked
    """
    raw = body or ""
    rawLow = raw.lower()
    token = (token or "").lower()
    lowerBodyQ = unquote_plus(raw).lower()
    lowerBodyU = unescape(raw).lower()

    # Token needs to appear in executable
    if token not in rawLow and token not in lowerBodyU and token not in lowerBodyQ:
        return False, None

    # Check raw non escaped block
    blocks = SCRIPT_BLOCK.findall(raw)
    if blocks:
        for blk in blocks:
            cleaned = JS_BLOCKCOM.sub("", blk)
            cleaned = JS_LINECOM.sub("", cleaned)
            cleaned = JS_STRINGS.sub("", cleaned)
            if token in cleaned.lower():
                log.debug("XSS detected: script_ctx (token=%s) [RAW script block]", token)
                return True, "script_ctx"

        # Checks if canary is inside JS String
        canaryJs = re.compile(r'(?:^|[^a-z0-9_])(?:window\.)?__xss_canary__\s*[:=]\s*["\']?\s*' + re.escape(token) + r'\s*["\']?',re.I)
        for blk in blocks:
            if canaryJs.search(blk.lower()):
                log.debug("XSS detected: script_ctx (token=%s) [RAW canary in script]", token)
                return True, "script_ctx"

    ATTR_TPL = cfg["xss"]["regex"]["attr"]
    JSURL_TPL = cfg["xss"]["regex"]["jsurl"]

    ATTR_RE = re.compile(ATTR_TPL.format(token=re.escape(token)), re.I | re.S)
    JSURL_RE = re.compile(JSURL_TPL.format(token=re.escape(token)), re.I | re.S)
    # Check if xss is in dangerous contexts
    if ATTR_RE.search(rawLow) or JSURL_RE.search(rawLow):
        log.debug("XSS detected: attr_ctx (token=%s) [RAW attribute/jsurl]", token)
        return True, "attr_ctx"

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