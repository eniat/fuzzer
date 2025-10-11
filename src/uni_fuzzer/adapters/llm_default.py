from typing import Optional, Any
from pathlib import Path

from ..llm.semantic_llm import filterML
from ..core.utility import get_cfg
from ..runtime.ports import LLMService

cfg = get_cfg()

class DefaultLLM(LLMService):
    """
        Wrapper for llm functions
    """
    def filter_ml(self, wordlist_path: Path, prompt: str, similarity: Optional[float] = None, util: Optional[Any] = None) -> list[str]:
        # If not given call with default
        if similarity is None:
            similarity = cfg["llm"]["similarity"]
        return filterML(wordlist_path, prompt, similarityThreshold=similarity, util=util)