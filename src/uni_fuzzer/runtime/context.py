from dataclasses import dataclass
from typing import Any
from .ports import AuthService, UtilService, DeteService, BaseService

@dataclass
class AppContext:
    auth: AuthService
    util: UtilService
    dete: DeteService
    base: BaseService
    cfg: dict[str, Any]
    args: Any