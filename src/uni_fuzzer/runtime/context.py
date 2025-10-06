from dataclasses import dataclass
from typing import Any
from .ports import AuthService, UtilService, DeteService, BaseService, ProbService

@dataclass
class AppContext:
    auth: AuthService
    util: UtilService
    dete: DeteService
    base: BaseService
    prob: ProbService
    cfg: dict[str, Any]
    args: Any