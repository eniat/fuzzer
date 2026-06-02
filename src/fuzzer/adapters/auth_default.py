import requests

from typing import Optional, Any, Sequence

from ..auth.auth import seleniumLogin, login, buildSessions
from ..runtime.ports import AuthService, UtilService

class DefaultAuth(AuthService):
    """
        Wrapper for auth functions
    """
    def __init__(self, util: UtilService | None = None):
        self.util = util

    def http_login(self, session: requests.Session, start_url: str, username: str,
                   password: str, login_path: Optional[str] = None,
                   selectors: Optional[dict[str,str]] = None,
                   headers: Optional[dict[str,str]] = None) -> bool:
        ok = login(session, start_url, username, password, login_path, selectors, headers)
        if not ok and self.util:
            self.util.status("[!] HTTP login failed")
        return ok

    def selenium_login(self, driver: Any, base_url: str, username: str,
                       password: str, login_path: Optional[str] = None,
                       selectors: Optional[dict[str,str]] = None) -> bool:
        ok = seleniumLogin(driver, baseUrl=base_url, username=username, password=password,
                           loginPath=login_path, selectors=selectors)
        if not ok and self.util:
            self.util.status("[!] Selenium login failed")
        return ok

    def build_sessions(self, auth: bool, username: Optional[str], password: Optional[str],
                       start_url: str, login_path: Optional[str],
                       desired_tasks: Optional[int] = None,
                       threads_per_sess: Optional[int] = None,
                       max_sess: Optional[int] = None,
                       pool_headroom: float = 0.25) -> Sequence[requests.Session]:
        pool = buildSessions(
            auth=auth, username=username, password=password,
            start_url=start_url, login_path=login_path,
            desiredTasks=desired_tasks, threadsPerSess=threads_per_sess,
            maxSess=max_sess, poolHeadroom=pool_headroom
        )
        if self.util and auth and (not pool):
            self.util.status(f"[-] Failed to create any authenticated sessions for {start_url}")
        return pool