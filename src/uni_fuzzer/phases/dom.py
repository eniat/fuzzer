import logging
import threading

from uni_fuzzer.core.fuzzer import FuzzerPhase, PhaseContext
from uni_fuzzer.core.utility import status
from uni_fuzzer.auth.auth import buildSessions
from uni_fuzzer.fuzzers.xss import XSSFuzzer

log = logging.getLogger(__name__)


class DomXSSPhase(FuzzerPhase):
    """
        Runs the dom fuzzer with the given args
    """

    def __init__(self, wordlistXss):
        self.wordlistXss = wordlistXss


    @property
    def name(self):
        return "XSS dom"


    def run(self, ctx: PhaseContext):
        """
            For the running of the Dom Phase
        """

        args = ctx.args

        # Check for wordlists and Forms if not set False
        if not self.wordlistXss or not ctx.forms:
            return []

        status(f"\n[+] Running Dom XSS on discovered forms/endpoints...\n")
        domSessPool = []
        domSess = None
        try:
            domSessPool = buildSessions(args.auth, args.username, args.password, args.start_url, args.login_path,
                                        desiredTasks=1,
                                        threadsPerSess=1,
                                        maxSess=1,
                                        poolHeadroom=0
                                        )
            domSess = domSessPool[0] if domSessPool else None
        except Exception:
            log.debug("Session pool build failed", exc_info=True)

        try:
            bail = threading.Event() if args.bail_on_hit else None
            xss_dom_fuzzer = XSSFuzzer(
                baseUrl=args.start_url,
                useCrawler=False,
                wordlistPath=self.wordlistXss,
                headless=not args.no_headless,
                session=domSess,
                auth=args.auth,
                loginUsername=args.username,
                loginPassword=args.password,
                loginPath=args.login_path,
                token=ctx.runToken,
                bailEvent=bail
            )

            return  xss_dom_fuzzer.domXSS(forms=ctx.forms, endpoints=ctx.endpoints)

        finally:
            if domSessPool:
                for sess in domSessPool:
                    try:
                        sess.close()
                    except Exception:
                        log.debug("Session close failed (dom)", exc_info=True)