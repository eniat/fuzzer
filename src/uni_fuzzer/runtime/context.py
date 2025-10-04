from dataclasses import dataclass
from typing import Any
from .ports import AuthService, UtilService, DeteService

@dataclass
class AppContext:
    auth: AuthService
    util: UtilService
    dete: DeteService
    cfg: dict[str, Any]
    args: Any