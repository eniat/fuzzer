import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List

@dataclass
class PhaseContext:
    args: Any
    cfg: Dict[str, Any]
    runToken: str
    endpoints: List[dict]
    forms: List[dict]
    baseUrl: str
    shared: Dict[str, Any]
    log: logging.Logger

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