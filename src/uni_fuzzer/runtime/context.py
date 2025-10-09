from dataclasses import dataclass
from typing import Any

from .ports import AuthService, UtilService, DeteService, BaseService, ProbService, RepoService, FuzzService, CrawService


@dataclass
class AppContext:
    auth: AuthService
    util: UtilService
    dete: DeteService
    base: BaseService
    prob: ProbService
    repo: RepoService
    fuzz: FuzzService
    craw: CrawService
    cfg: dict[str, Any]
    args: Any