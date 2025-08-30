from __future__ import annotations
from functools import lru_cache
from pathlib import Path
import yaml

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