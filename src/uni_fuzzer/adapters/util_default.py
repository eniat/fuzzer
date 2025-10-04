from typing import Optional, Any
from pathlib import Path

from ..core.utility import status, extractIdentifier ,isFuzzableField, loadWordlist, sortWordlist, collapseDuplicates, autoSubmits, getDirectories, getParents,isBlindPayload, buildBooleanPayloads,expandTimeToken, canary, BLIND_TIME
from ..runtime.ports import UtilService
from ..core.reporting import Finding

class DefaultUtil(UtilService):
    """
        Wrapper for utility functions
    """
    def status(self, msg: str, *args: Any) -> None:
        status(msg, *args)

    def extract_identifier(self, element: Any) -> Optional[str]:
        return extractIdentifier(element)
    def is_fuzzable_field(self, field: Optional[str]) -> bool:
        return isFuzzableField(field)

    def load_wordlist(self, path_or_list: Any) -> list[str]:
        return loadWordlist(path_or_list)
    def sort_wordlist(self, name_or_path: str) -> Path:
        return sortWordlist(name_or_path)

    def collapse_duplicates(self, items: list[Finding]) -> list[Finding]:
        return collapseDuplicates(items)

    def auto_submits(self, html: str, params: dict[str, str]) -> dict[str, str]:
        return autoSubmits(html, params)
    def get_directories(self, path: str) -> str:
        return getDirectories(path)
    def get_parents(self, path: str) -> list[str]:
        return getParents(path)

    def is_blind_payload(self, payload: Optional[str]) -> bool:
        return isBlindPayload(payload)
    def build_boolean_payloads(self) -> list[tuple[str, str]]:
        return buildBooleanPayloads()
    def expand_time_token(self, payload: Optional[str], seconds: float | int | None = None) -> str:
        if seconds is None:
            seconds = BLIND_TIME
        return expandTimeToken(payload, seconds=seconds)

    def canary(self, payload: Optional[str], token: str) -> str:
        return canary(payload, token)