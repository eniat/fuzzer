import logging
import re
import yaml
import posixpath

from functools import lru_cache
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse, unquote

from ..core.reporting import Finding

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
    emitted: list[Finding] = []

    cfg = get_cfg()

    # List of vuln files
    SENSITIVE_FILES = cfg["paths"]["sensitive_files"]
    FILE_EXTENSIONS = tuple(cfg["paths"]["file_extensions"] or ())
    XSS_MAX_SAMPLES = cfg["xss"]["max_samples_per_group"]
    PATH_MAX_SAMPLES = cfg["path_traversal"]["max_samples_per_group"]
    SQLI_MAX_SAMPLES =cfg["sqli"]["max_samples_per_group"]

    for item in (items or []):
        rawUrl = (getattr(item, "url", "") or "").strip()

        if not rawUrl:
            continue

        typ = (getattr(item, "type", "") or "").lower()
        indicator = (getattr(item, "indicator", "") or "N/A").strip()
        param = getattr(item, "param", None)

        try:
            # Consistent normalization
            parsed = urlparse(rawUrl)
            scheme = (parsed.scheme or "").lower()
            host = (parsed.netloc or "").lower()
            path = unquote(parsed.path or "/")
            path = posixpath.normpath(path)

            if not path.startswith("/"):
                path = "/" + path

            if path != "/" and path.endswith("/"):
                path = path.rstrip("/")
        except Exception:

            scheme, host, path = "", "", (rawUrl or "/")

        # Work out a group path
        try:
            baseC = (path.rsplit("/", 1)[-1] if path else "").lower()
            queryL = (parsed.query or "").lower()

            files = (baseC.endswith(FILE_EXTENSIONS) or baseC in SENSITIVE_FILES)
            query = None

            if not files and queryL:
                for name in SENSITIVE_FILES:
                    if name in queryL:
                        query = name
                        break

            # As more variants for path/param due to payload similarity tighter group
            if ("path" in typ) or ("param" in typ):
                if files:
                    groupPath = "/" + baseC
                elif query:
                    groupPath = "/" + query
                else:
                    groupPath = path
            else:
                groupPath = path
        except Exception:
            groupPath = path

        pageUrl = f"{scheme}://{host}{groupPath}"

        key = (typ, host, groupPath, indicator, param)

        if key not in groups:
            rep = Finding(
                type=typ or "unknown",
                url=pageUrl,
                method=(getattr(item, "method", "GET") or "GET"),
                param=param,
                payload=getattr(item, "payload", None),
                indicator=indicator,
                status_code=getattr(item, "status_code", None),
                count=0,
                payload_samples=[],
                response_snippet=((getattr(item, "response_snippet", "") or "")[:200])
            )
            groups[key] = rep
            emitted.append(rep)

        rep = groups[key]

        try:
            rep.count = int(rep.count or 0) + (int(getattr(item, "count", 0) or 1))
        except Exception:
            rep.count = (rep.count or 0) + 1

        # Keep highest status code achieved
        try:
            if int(getattr(item, "status_code", 0) or 0) > int(getattr(rep, "status_code", 0) or 0):
                rep.status_code = item.status_code
        except Exception:
            pass

        if not rep.payload:
            rep.payload = getattr(item, "payload", None)

        # Assign sample caps
        try:
            if typ.startswith("xss"):
                cap = XSS_MAX_SAMPLES
            elif "sqli" in typ:
                cap = SQLI_MAX_SAMPLES
            elif ("path" in typ) or ("param" in typ):
                cap = PATH_MAX_SAMPLES
            else:
                cap = 3
        except Exception:
            cap = 3

        samples = list(getattr(item, "payload_samples", []) or [])
        if not samples and getattr(item, "payload", None) is not None:
            samples = [item.payload]

        if samples:
            seen = set(rep.payload_samples or [])
            for samp in samples:
                if samp is None:
                    continue
                if len(rep.payload_samples) >= cap:
                    break
                if samp not in seen:
                    rep.payload_samples.append(samp)
                    seen.add(samp)

        if (rep.indicator or "N/A") == "N/A":
            ind = (getattr(item, "indicator", "") or "").strip()
            if ind:
                rep.indicator = ind
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
