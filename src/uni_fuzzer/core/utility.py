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