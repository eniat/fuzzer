from typing import Optional, Tuple
from requests import Response

from ..fuzzers.detection import detectXSS ,detectSQLError, detectSQLiBlind, detectSQLiDiff, detectPathTraversal

from ..core.utility import get_cfg
from ..runtime.ports import DeteService

cfg = get_cfg()

class DefaultDete(DeteService):
    """
        Wrapper for auth functions
    """

    def detect_xss(self, body: str, token: str) -> Tuple[bool, Optional[str]]:
        return detectXSS(body, token)

    def detect_sql_error(self, body: str) -> Tuple[bool, Optional[str]]:
        return detectSQLError(body)

    def detect_sqli_blind(self, base_ms: float, test_ms: float,
                          threshold_ms: Optional[int] = None,
                          factor: Optional[float] = None) -> bool:
        if threshold_ms is None:
            threshold_ms = cfg["sqli"]["timing_threshold_ms"]
        if factor is None:
            factor = cfg["sqli"]["blind_timing_factor"]
        return detectSQLiBlind(base_ms, test_ms, threshold_ms, factor)

    def detect_sqli_diff(self, base_html: str, html: str,
                         is_not_sqli_blind: bool = True,
                         true: Optional[str] = None,
                         false: Optional[str] = None,
                         payload: Optional[str] = None) -> bool:
        return detectSQLiDiff(base_html, html,
                              isNotSQLIBlind=is_not_sqli_blind,
                              true=true, false=false, payload=payload)

    def detect_path_traversal(self, response: Response,
                              baseline: Optional[dict] = None,
                              similarity_skip_threshold: Optional[float] = None):
        return detectPathTraversal(response, baseline, similarity_skip_threshold)
