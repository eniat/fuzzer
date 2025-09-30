from __future__ import annotations

import logging
import re
from functools import lru_cache
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse, unquote
import yaml
import posixpath

from uni_fuzzer.core.reporting import Finding

log = logging.getLogger(__name__)

@lru_cache(maxsize=1)

def get_cfg():
    here = Path(__file__).resolve().parent.parent / "config" / "defaults.yaml"
    with open(here, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def isFuzzableField(field):
    """
        Check if form field is fuzzable
    """

    if not field:
        return False

    lowered = field.lower()
    cfg = get_cfg()

    # List of skips to avoid useless form fuzzing
    skips = cfg["fuzz"]["skipped_fields"]

    return not any(skip in lowered for skip in skips)

def loadWordlist(path):
    """
        Load payload from wordlist
    """
    # Check if list is passed via LLM
    if isinstance(path, list):
        return path

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            # Strips the lines
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        # On error raise exception
        raise RuntimeError(f"[-] Failed to load wordlist from {path}: {e}")

def collapseDuplicates (items: list[Finding]) -> list[Finding]:
    """
        Collapses duplicates that go into the same normalised path
    """
    groups = {}
    storedGroups = {}
    xssGroups = {}
    emitted: list[Finding] = []

    cfg = get_cfg()

    # List of vuln files
    SENSITIVE_FILES = cfg["paths"]["sensitive_files"]
    FILE_EXTENSIONS = cfg["paths"]["file_extensions"]
    COLLAPSIBLE_TYPES = cfg["paths"]["collapsible_types"]
    XSS_MAX_SAMPLES = cfg["xss"]["max_samples_per_group"]
    PATH_MAX_SAMPLES = cfg["path_traversal"]["max_samples_per_group"]

    for item in items or []:
        rawUrl = (item.url or "").strip()
        typ = (item.type or "").lower()

        if not rawUrl:
            continue

        # Purely collapse XSS_stored as each thread checks all endpoints
        if typ == "xss_stored":
            p = urlparse(rawUrl)
            scheme = (p.scheme or "").lower()
            host = (p.netloc or "").lower()
            path = p.path or "/"

            # Normalise ands strip
            if path != "/" and path.endswith("/"):
                path = path.rstrip("/")

            pageUrl = f"{scheme}://{host}{path}"
            indicator = (item.indicator or "N/A")

            skey = (typ, host, path, indicator)

            count = int(item.count or 0)
            samples = list(item.payload_samples or [])

            if not samples and item.payload is not None:
                samples = [item.payload]

            if skey not in storedGroups:
                rep = Finding(
                    type=typ,
                    url=pageUrl,
                    method=item.method or "GET",
                    param=item.param,
                    payload=item.payload,
                    indicator=indicator,
                    status_code=item.status_code,
                    count=0,
                    payload_samples=[],
                    response_snippet=(item.response_snippet or "")[:200]
                )
                rep.count = (rep.count or 0) + (count or 1)
                for sample in samples:
                    if sample is not None and len(rep.payload_samples) < XSS_MAX_SAMPLES:
                        if sample not in rep.payload_samples:
                            rep.payload_samples.append(sample)

                storedGroups[skey] = rep
                emitted.append(rep)

            else:
                rep = storedGroups[skey]

                rep.count = (rep.count or 0) + (count or 1)

                for sample in samples:
                    if sample is not None and len(rep.payload_samples) < XSS_MAX_SAMPLES:
                        if sample not in rep.payload_samples:
                            rep.payload_samples.append(sample)

                try:
                    if int(item.status_code or 0) > int(rep.status_code or 0):
                        rep.status_code = item.status_code
                except Exception:
                    log.debug("Failed to update status_code in stored XSS group", exc_info=True)

            continue

        # Collapse the other xss
        if typ in ("xss_form", "xss_param", "xss_dom"):
            p = urlparse(rawUrl)
            scheme = (p.scheme or "").lower()
            host = (p.netloc or "").lower()
            path = p.path or "/"

            # Normalize path
            if path != "/" and path.endswith("/"):
                path = path.rstrip("/")

            pageUrl = f"{scheme}://{host}{path}"
            indicator = (item.indicator or "N/A")
            key = (typ, host, path, indicator)

            # counts and samples
            count = int(item.count or 0)
            samples = list(item.payload_samples or [])
            if not samples and item.payload is not None:
                samples = [item.payload]

            if key not in xssGroups:
                rep = Finding(
                    type=typ,
                    url=pageUrl,
                    method=item.method or "GET",
                    param=item.param,
                    payload=item.payload,
                    indicator=indicator,
                    status_code=item.status_code,
                    count=0,
                    payload_samples=[],
                    response_snippet=(item.response_snippet or "")[:200]
                )
                rep.count = (rep.count or 0) + (count or 1)

                for sample in samples:
                    if sample is not None and len(rep.payload_samples) < XSS_MAX_SAMPLES:
                        if sample not in rep.payload_samples:
                            rep.payload_samples.append(sample)

                xssGroups[key] = rep
                emitted.append(rep)

            else:
                rep = xssGroups[key]
                rep.count = (rep.count or 0) + (count or 1)

                for sample in samples:
                    if sample is not None and len(rep.payload_samples) < XSS_MAX_SAMPLES:
                        if sample not in rep.payload_samples:
                            rep.payload_samples.append(sample)

                try:
                    if int(item.status_code or 0) > int(rep.status_code or 0):
                        rep.status_code = item.status_code
                except Exception:
                    log.debug("Failed to update status_code in XSS group", exc_info=True)

            continue

        # Only collapse path and param findings to avoid XSS/ SQLI ect
        isFile = ( typ in COLLAPSIBLE_TYPES)

        if not isFile:
            emitted.append(item)
            continue

        p = urlparse(rawUrl)
        host = (p.netloc or "").lower()
        scheme = (p.scheme or "").lower()
        path = unquote(p.path or "/")
        query = unquote(p.query or "")

        # Normalise the path
        normPath = posixpath.normpath(path)
        if not normPath.startswith("/"):
            normPath = "/" + normPath

        # remove slash
        if normPath != "/" and normPath.endswith("/"):
            normPath = normPath.rstrip("/")

        # Traversal variants cs direct hits
        rawLower = ((p.path or "") + "?" + (p.query or "")).lower()
        hadTraversal = ("/../" in rawLower or rawLower.startswith("../") or "%2e%2e" in rawLower or "%2f..%2f" in rawLower or "/..\\" in rawLower or "\\..\\" in rawLower or "/%2e%2e/" in rawLower)

        # Try to find the target
        targetBase = None
        queryLow = query.lower()
        for name in SENSITIVE_FILES:
            if name in queryLow:
                targetBase = name
                break

        if not targetBase:
            baseCandidate = normPath.rsplit("/", 1)[-1].lower()
            if baseCandidate.endswith(tuple(FILE_EXTENSIONS)) or baseCandidate in SENSITIVE_FILES:
                targetBase = baseCandidate

        groupPath = f"/{targetBase}" if targetBase and not targetBase.startswith("/") else (targetBase or normPath)

        # Include type so path and param aren't merged
        key = (typ, host, groupPath)

        if key not in groups:
            rep = Finding(
                type=typ or "path",
                url=f"{scheme}://{host}{groupPath}",
                method=item.method or "GET",
                param=item.param,
                payload=item.payload,
                indicator=(item.indicator or "N/A").strip(),
                status_code=item.status_code,
                count=0,
                payload_samples=[],
                response_snippet=(item.response_snippet or "")[:200]
            )
            groups[key] = {
                "rep": rep,
                "variant_path_count": 0,
                "variant_samples": [],
                "had_traversal": False,
            }
            emitted.append(rep)

        group = groups[key]
        group["variant_path_count"] += 1

        if len(group["variant_samples"]) < PATH_MAX_SAMPLES:
            group["variant_samples"].append(rawUrl)

        group["had_traversal"] = group["had_traversal"] or hadTraversal

        rep = group["rep"]
        # Prefer first
        if not rep.payload:
            rep.payload = item.payload

        ind = (item.indicator or "").strip()
        if ind and (rep.indicator or "N/A") == "N/A":
            rep.indicator = ind

        try:
            if int(item.status_code or 0) > int(rep.status_code or 0):
                rep.status_code = item.status_code

        except Exception:
            log.debug("Failed to update status_code in path/param group", exc_info=True)

        rep.count = group["variant_path_count"]
        rep.payload_samples = group["variant_samples"][:]

    return emitted

def autoSubmits(html, params):
    """
        If there is a button summits it with the name as the field
    """
    cfg = get_cfg()
    AUTO_SUBMIT_KEYS = cfg["paths"]["auto_submit_keys"]

    if not html:
        return params

    lowHtml = html.lower()
    for key in AUTO_SUBMIT_KEYS:
        if not key:
            continue
        if key in lowHtml:
            params[key.capitalize()] = key.capitalize()
    return params

WORDLIST_DIR = Path(__file__).resolve().parent.parent / "resources" / "wordlists"

def sortWordlist(name):
    """
        Allows wordlist to be passed by name as well as full file location
    """
    # if it's a path that's valid return path
    p = Path(name)
    if p.exists():
        return p

    # Check resources/wordlists by short name
    candidate = WORDLIST_DIR / f"{name}.txt"
    if candidate.exists():
        return candidate

    raise FileNotFoundError(f"Wordlist '{name}' not found in {WORDLIST_DIR}")

def getDirectories(path):
    """
        Helper for stripping filenames and only leaving directories
    """

    cfg = get_cfg()
    exts = cfg["paths"]["file_extensions"]

    segments = path.rstrip("/").split("/")

    if segments and any(segments[-1].lower().endswith(ext) for ext in exts):
        segments = segments[:-1]

    baseDir = "/" + "/".join(segments) if segments else "/"
    return str(PurePosixPath(baseDir))

def getParents(path):
    """
        Gets the parents of the given URL
    """
    p = PurePosixPath(urlparse(path).path or "/")

    chain = []
    for parent in p.parents:
        if str(parent) != ".":
            chain.append(str(parent) if str(parent).startswith("/") else f"/{parent}")

    chain.append(str(p) if str(p).startswith("/") else f"/{p}")

    # normalize and dedupe
    seen, out = set(), []

    for x in chain:
        n = str(PurePosixPath(x)).rstrip("/") or "/"
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out

cfg = get_cfg()
BLIND_MARKERS = cfg["sqli"]["blind_markers"]
BLIND_TIME = cfg["sqli"]["blind_time"]
BOOLEAN_TRUE  = cfg["sqli"]["boolean_true"]
BOOLEAN_FALSE = cfg["sqli"]["boolean_false"]
BOOLEAN_WRAPPERS = cfg["sqli"]["boolean_wrappers"]

def isBlindPayload (payload):
    """
        Checks if payload is a blind payload
    """
    low = (payload or "").lower()
    return any(mark in low for mark in BLIND_MARKERS)

def buildBooleanPayloads():
    """
        Builds boolean true/false payload pairs for blind sqli boolean tests
    """
    payloadPairs = []
    for wrap in BOOLEAN_WRAPPERS:
        for true, false in zip(BOOLEAN_TRUE, BOOLEAN_FALSE):
            payloadPairs.append((
                wrap.format(cond=true),
                wrap.format(cond=false)
            ))
    return payloadPairs

def expandTimeToken(payload, seconds=BLIND_TIME):
    """
        Replaces __TIME__ in payload strings with the configured number of seconds
    """
    return (payload or "").replace("__TIME__", str(seconds))

def canary(payload, token):
    """
        Append payload with unique token
    """
    striped = (payload or "").strip()
    token = token
    low = striped.lower()
    # Javascript
    if low.startswith("javascript:"):
        return striped + ("" if striped.rstrip().endswith(";") else ";") + 'window.__XSS_CANARY__="' + token + '"'

    # <script>
    mes = re.search(r'(<\s*script\b[^>]*>)(.*?)(</\s*script\s*>)', striped, re.I | re.S)
    if mes:
        body = mes.group(2)
        sep = "" if body.rstrip().endswith(";") else ";"
        return mes.group(1) + body + sep + 'window.__XSS_CANARY__="' + token + '"' + mes.group(3)

    # inline handlers
    new = re.sub(r'(\bon[a-z]+\s*=\s*)(["\'])(.*?)\2', r'\1\2\3;window.__XSS_CANARY__="' + token + r'"\2', striped, flags=re.I | re.S)
    if new != striped:
        return new
    new = re.sub(r'(\bon[a-z]+\s*=\s*)([^\'"\s>]+)', r'\1\2;window.__XSS_CANARY__="' + token + r'"', striped, flags=re.I)
    if new != striped:
        return new

    # HTML
    if "<" in striped and ">" in striped:
        mes = re.search(r'\s*<\s*(?!/)([a-z0-9:-]+)([^>]*)>', striped, re.I)
        if mes:
            indexAt = mes.end() - 1
            striped = striped[:indexAt] + ' data-canary="' + token + '"' + striped[indexAt:]
        return striped + '<script>window.__XSS_CANARY__="' + token + '"</script>'

    # plain
    return striped + ';window.__XSS_CANARY__="' + token + '";'

def extractIdentifier(el):
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

    junkKeywords = cfg["crawler"]["junk_keywords"]

    if any(junk in normalized for junk in junkKeywords):
        return None


    return raw.strip()

def status (msg, *args):
    """
        To avoid duplicates when console logging is on
    """
    # Prepare message
    text = (msg % args) if args else msg

    rootLogger = logging.getLogger()
    isConfigured = getattr(rootLogger, "_uf_configured", False)
    hasConsole = False

    # if it is configured then check if console stderr is attached
    if isConfigured:
        for hand in rootLogger.handlers:
            if isinstance(hand, logging.StreamHandler) and not hasattr(hand, "baseFilename"):
                hasConsole = True
                break

    # If it is configured then send to logger
    if isConfigured:
        logging.getLogger("status").info(text)

    # If not then print to console so user can see
    if not isConfigured or not hasConsole:
        print(text, flush=True)
