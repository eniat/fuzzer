import requests

from requests import Response
from pathlib import Path
from typing import Protocol, Optional, Any, Sequence, Tuple

from ..core.reporting import Finding

class AuthService(Protocol):
    """
        Port for Auth.py
    """
    def http_login(self, session: requests.Session, start_url: str, username: str,
                   password: str, login_path: Optional[str] = None,
                   selectors: Optional[dict[str,str]] = None,
                   headers: Optional[dict[str,str]] = None) -> bool: ...

    def selenium_login(self, driver: Any, base_url: str, username: str,
                       password: str, login_path: Optional[str] = None,
                       selectors: Optional[dict[str,str]] = None) -> bool: ...

    def build_sessions(self, auth: bool, username: Optional[str], password: Optional[str],
                       start_url: str, login_path: Optional[str],
                       desired_tasks: Optional[int] = None,
                       threads_per_sess: Optional[int] = None,
                       max_sess: Optional[int] = None,
                       pool_headroom: float = 0.25) -> Sequence[requests.Session]: ...

class UtilService(Protocol):
    """
        Port for Utility.py
    """
    def status(self, msg: str, *args: Any) -> None: ...

    def extract_identifier(self, element: Any) -> Optional[str]: ...
    def is_fuzzable_field(self, field: Optional[str]) -> bool: ...

    def load_wordlist(self, path_or_list: Any) -> list[str]: ...
    def sort_wordlist(self, name_or_path: str) -> Path: ...

    def collapse_duplicates(self, items: list[Finding]) -> list[Finding]: ...

    def auto_submits(self, html: str, params: dict[str, str]) -> dict[str, str]: ...
    def get_directories(self, path: str) -> str: ...
    def get_parents(self, path: str) -> list[str]: ...

    def is_blind_payload(self, payload: Optional[str]) -> bool: ...
    def build_boolean_payloads(self) -> list[tuple[str, str]]: ...
    def expand_time_token(self, payload: Optional[str], seconds: int | float = ...) -> str: ...

    def canary(self, payload: Optional[str], token: str) -> str: ...

class DeteService(Protocol):
    """
        Port for Detection.py
    """
    def detect_xss(self, body: str, token: str) -> Tuple[bool, Optional[str]]: ...

    def detect_sql_error(self, body: str) -> Tuple[bool, Optional[str]]: ...

    def detect_sqli_blind(self, base_ms: float, test_ms: float,
                          threshold_ms: Optional[int] = None,
                          factor: Optional[float] = None) -> bool: ...

    def detect_sqli_diff(self, base_html: str, html: str,
                         is_not_sqli_blind: bool = True,
                         true: Optional[str] = None,
                         false: Optional[str] = None,
                         payload: Optional[str] = None) -> bool: ...

    def detect_path_traversal(self, response: "Response",
                              baseline: Optional[dict] = None,
                              similarity_skip_threshold: Optional[float] = None
                              ) -> Tuple[str, Optional[Any]]: ...