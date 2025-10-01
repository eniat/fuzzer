import logging
import requests

from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter

from uni_fuzzer.core.utility import get_cfg

log = logging.getLogger(__name__)

class AbstractFuzzer (ABC):

    def __init__(self, baseUrl, session=None, headers =None, wordlistPath= None, bailEvent=None, cfg=None):
        self.baseUrl = baseUrl
        self.wordlistPath = wordlistPath
        self.cfg = cfg or get_cfg()
        self.headers = headers or {"User-Agent": self.cfg["http"]["user_agent"]}
        self.bailEvent = bailEvent
        self.session = session

        # Create session if none given
        if self.session is None:
            self.session = requests.Session()
            mw = int(self.cfg["concurrency"]["max_workers"])
            adapter = HTTPAdapter(pool_connections=mw, pool_maxsize=mw, max_retries=0)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
            self.session.trust_env = False

    def prepare(self, ctx):
        """
            Optional for baselines, probes ect
        """
        return None


    @abstractmethod
    def analyzeResponse(self, response, meta):
        """
            Return a Finding
        """
        ...


    def sendRequest(self, method, url, **kwargs):
        """
            Send a request
        """
        # If bail on first then bail
        if self.bailEvent and getattr(self.bailEvent, "is_set", lambda: False)():
            return  None

        try:
            # To allow overrides
            allow = kwargs.pop("allow_redirects", None)
            timeout = kwargs.pop("timeout", None)

            kwargs.setdefault("headers", self.headers)
            if method.upper() == "POST":
                if allow is None:
                    allow = self.cfg["http"]["redirects"]["fuzz_post"]
                if timeout is None:
                    timeout = self.cfg["http"]["timeout_post_seconds"]
                return self.session.post( url, timeout=timeout, allow_redirects=allow, **kwargs)

            else:
                if allow is None:
                    allow = self.cfg["http"]["redirects"]["fuzz_get"]
                if timeout is None:
                    timeout = self.cfg["http"]["timeout_get_seconds"]
                return self.session.get(url, timeout=timeout, allow_redirects=allow, **kwargs)

        except Exception:
            log.debug("sendRequest failed: %s %s", method, url, exc_info=True)
            return None

    def runBatch (self, requestsList, concurrency =None, collectRaw=False):
        """
            Run a batch of requests and return the findings
        """

        findings = []
        if not requestsList:
            return findings

        max_workers = concurrency or int(self.cfg["concurrency"]["max_workers"])

        with ThreadPoolExecutor(max_workers= max_workers) as executor:
            futures = {}
            for method, url, kwargs, meta in requestsList:
                if self.bailEvent and self.bailEvent.is_set():
                    break

                fut = executor.submit(self.sendRequest, method, url, **(kwargs or {}))
                futures[fut] = meta

            for fut in as_completed(futures):
                if self.bailEvent and self.bailEvent.is_set():
                    break

                try:
                    res = fut.result()

                except Exception:
                    log.debug("Future failed in runBatch", exc_info=True)
                    continue

                if not res:
                    continue

                meta = futures[fut] or {}

                # If raw responses required
                if collectRaw:
                    findings.append((res, meta))
                    continue

                try:
                    finding = self.analyzeResponse(res, meta)

                except Exception:
                    log.debug("analyzeResponse failed", exc_info=True)
                    continue

                if finding:
                    findings.append(finding)
                    bail = getattr(finding, "bail", False)
                    if self.bailEvent and bail:
                        self.bailEvent.set()
                        break
        return findings