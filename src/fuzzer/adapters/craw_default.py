from concurrent.futures import ThreadPoolExecutor
from typing import Any, cast, Callable

from ..runtime.ports import CrawService, Crawler
from ..crawler.static_crawler import StaticCrawler
from ..crawler.dynamic_crawler import DynamicCrawler

class BothCrawler:
    """
        Wrapper for running both Crawlers
    """
    name = "both"

    def __init__(self, **kwargs: Any) -> None:

        self.static = StaticCrawler(**kwargs)
        self.dynamic = DynamicCrawler(**kwargs)

    def run(self, start_url: str, ctx=None):
        # Run both in parallel to speed up
        with ThreadPoolExecutor(max_workers=2) as ex:
            static = ex.submit(self.static.run, start_url, ctx)
            dynamic = ex.submit(self.dynamic.run, start_url, ctx)
            sEnd, sForms = static.result()
            dEnd, dForms = dynamic.result()

        # merge retreived endpoints
        eMap: dict[tuple[str,str], set[str]] = {}

        for src in (sEnd, dEnd):
            for end in src:
                key = (end["url"], end["method"])

                eMap.setdefault(key, set()).update(end.get("params", []))

        endpoints = [{"url": url, "method": meth, "params": sorted(list(params))}for (url, meth), params in eMap.items()]

        # merge retrieved forms
        fMap: dict[tuple[str,str], set[str]] = {}

        for src in (sForms, dForms):
            for form in src:
                key = (form["url"], form["method"])

                fMap.setdefault(key, set()).update(form.get("formFields", []))

        forms = [{"url": url, "method": meth, "formFields": sorted(list(forms))}for (url, meth), forms in fMap.items()]

        return endpoints, forms


class DefaultCraw(CrawService):
    """
        Wrapper for Crawlers
    """
    def __init__(self) -> None:
        self.reg: dict[str, Any] = {
            "static": StaticCrawler,
            "dynamic": DynamicCrawler,
            "both": BothCrawler
        }

    def has(self, kind: str) -> bool:
        return kind in self.reg

    def create(self, kind: str, **kwargs: Any) -> Crawler:  # type: ignore[override]
        factory = cast(Callable[..., Crawler], self.reg[kind])
        return factory(**kwargs)