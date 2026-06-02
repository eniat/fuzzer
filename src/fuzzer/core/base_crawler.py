import requests

from abc import ABC, abstractmethod
from requests.adapters import HTTPAdapter

from .utility import get_cfg
from ..runtime.context import AppContext

cfg = get_cfg()

class BaseCrawler(ABC):

    def __init__(self, *, maxPages=None, rateLimit=None, headless=None, auth=False, loginUsername=None, loginPassword=None, loginPath=None, ctx: AppContext | None = None):
        self.ctx = ctx
        if self.ctx is None:
            raise ValueError("Crawler requires an AppContext")

        # Crawler settings
        self.maxPages = maxPages if maxPages is not None else cfg["crawler"]["max_pages_default"]
        self.rateLimit = rateLimit if rateLimit is not None else cfg["crawler"]["rate_limit_default"]
        self.headless = headless if headless is not None else cfg["crawler"]["headless_default"]

        self.auth = auth
        self.loginUsername = loginUsername
        self.loginPassword = loginPassword
        self.loginPath = loginPath

        # Storage for results
        self.discoveredEndpoints = []
        self.discoveredForms = []

        self.session = requests.Session()

        mw = int(cfg["concurrency"]["max_workers"])
        adapter = HTTPAdapter(pool_connections=mw, pool_maxsize=mw, max_retries=0)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.trust_env = False


    @ abstractmethod
    def run(self, startUrl, ctx):
        """
            Returns the endpoints and forms after crawling
        """
        return