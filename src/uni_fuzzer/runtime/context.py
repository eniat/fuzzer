from dataclasses import dataclass
from typing import Any

from .ports import AuthService, UtilService, DeteService, BaseService, ProbService, RepoService, FuzzService


@dataclass
class AppContext:
    auth: AuthService
    util: UtilService
    dete: DeteService
    base: BaseService
    prob: ProbService
    repo: RepoService
    fuzz: FuzzService
    cfg: dict[str, Any]
    args: Any