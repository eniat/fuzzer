from __future__ import annotations
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse, unquote
import yaml
import posixpath
import re

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

def collapseDuplicates(items):
    """
        Collapses duplicates that go into the same normalised path
    """
    groups = {}
    passthrough = []

    cfg = get_cfg()

    # List of vuln files
    SENSITIVE_FILES = cfg["paths"]["sensitive_files"]
    FILE_EXTENSIONS = cfg["paths"]["file_extensions"]
    COLLAPSIBLE_TYPES = cfg["paths"]["collapsible_types"]

    for item in items or []:
        rawUrl = (item.get("url") or "").strip()
        typ = (item.get("type") or "").lower()

        if not rawUrl:
            continue

        # Only collapse path and param findings to avoid XSS/ SQLI ect
        isFile = ( typ in COLLAPSIBLE_TYPES)

        if not isFile:
            passthrough.append(item)
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
            rep = {
                "url": f"{scheme}://{host}{groupPath}",
                "payload": item.get("payload"),
                "status_code": item.get("status_code"),
                "indicator": (item.get("indicator") or "N/A"),
                "snippet": (item.get("snippet") or "")[:200],
                "type": typ or "path",
                "variant_path_count": 0,
                "variant_samples": [],
                "had_traversal": False,
            }
            groups[key] = rep

        group = groups[key]
        group["variant_path_count"] += 1

        if len(group["variant_samples"]) < 5:
            group["variant_samples"].append(rawUrl)

        group["had_traversal"] = group["had_traversal"] or hadTraversal

        # Prefer first
        if not group.get("payload"):
            group["payload"] = item.get("payload")
        ind = (item.get("indicator") or "").strip()

        if ind and group.get("indicator", "N/A") == "N/A":
            group["indicator"] = ind

        try:
            if int(item.get("status_code") or 0) > int(group.get("status_code") or 0):
                group["status_code"] = item.get("status_code")

        except Exception:
            pass

    collapsed = list(groups.values())

    return collapsed + passthrough

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
