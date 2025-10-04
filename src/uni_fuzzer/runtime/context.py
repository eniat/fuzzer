from dataclasses import dataclass
from typing import Any
from .ports import AuthService, UtilService

@dataclass
class AppContext:
    auth: AuthService
    util: UtilService
    cfg: dict[str, Any]
    args: Any