from typing import Any, cast, Callable

from ..runtime.ports import FuzzService, Fuzzer
from ..fuzzers.xss_dom import DomXSSFuzzer
from ..fuzzers.xss_form import FormXSSFuzzer
from ..fuzzers.xss_stored import StoredXSSFuzzer
from ..fuzzers.xss_param import ParamXSSFuzzer
from ..fuzzers.sql_inj import InjSQLFuzzer
from ..fuzzers.sql_iblind import BlindSQLiFuzzer
from ..fuzzers.path_traversal import TraversalPathFuzzer
from ..fuzzers.path_param import ParamPathFuzzer

class DefaultFuzz(FuzzService):
    """
        Wrapper for Fuzzers
    """
    def __init__(self) -> None:
        self.reg: dict[str, Any] = {
            "xss_form": FormXSSFuzzer,
            "xss_stored": StoredXSSFuzzer,
            "xss_param": ParamXSSFuzzer,

            "xss_dom": DomXSSFuzzer,
            "sqli": InjSQLFuzzer,
            "sqli_blind": BlindSQLiFuzzer,
            "path": TraversalPathFuzzer,
            "param": ParamPathFuzzer,
        }

    def has(self, kind: str) -> bool:
        return kind in self.reg

    def create(self, kind: str, **kwargs: Any) -> Fuzzer:  # type: ignore[override]
        factory = cast(Callable[..., Fuzzer], self.reg[kind])
        return factory(**kwargs)