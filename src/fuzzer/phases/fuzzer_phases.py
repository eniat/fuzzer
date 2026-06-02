import logging

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List

from ..runtime.context import AppContext

@dataclass
class PhaseContext:
    args: Any
    cfg: Dict[str, Any]
    endpoints: List[dict]
    forms: List[dict]
    rawForms: List[dict]
    baseUrl: str
    shared: Dict[str, Any]
    log: logging.Logger
    runtime: AppContext | None = None

class FuzzerPhase(ABC):
    """
        Minimal Interface to keep the controller light
    """

    @property
    @abstractmethod
    def name(self):
        ...

    def prepare(self, ctx: PhaseContext):
        return None

    @abstractmethod
    def run (self, ctx:PhaseContext):
        ...

    def teardown(self, ctx:PhaseContext):
        return None