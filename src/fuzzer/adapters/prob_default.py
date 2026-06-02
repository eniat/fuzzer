import requests

from typing import Optional, Any

from ..core.probes import probeReactivity, probeDom, probeReflexivity
from ..runtime.ports import ProbService, DeteService


class DefaultProb(ProbService):
    """
        Wrapper for Probes functions
    """
    def probe_reactivity(self, session: requests.Session, url: str, method: str, fields: list[str],
                         fuzz_field: list[str], dete: Optional["DeteService"] = None, headers: Optional[dict[str,str]] = None) -> bool:
        return probeReactivity(session, url, method, fields, fuzz_field, dete, headers)

    def probe_dom(self, driver: Any, token_low: str) -> dict[str, bool]:
        return probeDom(driver, token_low)

    def probe_reflexivity(self, session: requests.Session, url: str, method: str, fields: list[str],
                          fuzz_field: str, token: str, headers: Optional[dict[str,str]] = None) -> bool:
        return probeReflexivity(session, url, method, fields, fuzz_field, token, headers)