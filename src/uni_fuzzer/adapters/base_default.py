from typing import Optional, Tuple

import requests

from ..core.baseline import baselineForm,getBaseline, sqliBaseline, getBlindBaseline
from ..runtime.ports import BaseService, UtilService


class DefaultBase(BaseService):
    """
        Wrapper for Baseline functions
    """
    def baseline_form(self,session: requests.Session, url: str, headers: Optional[dict[str,str]] = None) -> dict[str]:
        return baselineForm(session, url, headers)

    def get_baseline(self,session: requests.Session, url: str, headers: Optional[dict[str,str]] = None) -> dict[str, str]:
        return getBaseline(session, url, headers)

    def sqli_baseline(self,session: requests.Session, endpoint : str, method: str , field: list[str],
                      util: "UtilService", headers: Optional[dict[str,str]] = None) -> Tuple[str, int]:
        return sqliBaseline(session,headers, endpoint, method, field, util )

    def get_blind_baseline(self,session: requests.Session, endpoint : str, method: str , field: list[str],
                           util: "UtilService", probes: Optional[int], headers: Optional[dict[str,str]] = None) -> float:
        return getBlindBaseline(session, headers, endpoint, method, field, util, probes)