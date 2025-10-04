import logging
import threading

from uuid import uuid4

from ..fuzzers.xss_dom import DomXSSFuzzer

from ..phases.fuzzer_phases import FuzzerPhase, PhaseContext

log = logging.getLogger(__name__)

class DomXSSPhase(FuzzerPhase):
    """
        Runs the dom fuzzer with the given args
    """


    @property
    def name(self):
        return "XSS dom"


    def run(self, ctx: PhaseContext):
        """
            For the running of the Dom Phase
        """

        args = ctx.args
        runToken = f"XSSCanary-{uuid4().hex[:8]}"

        forms = ctx.rawForms or []
        endpoints = ctx.endpoints or []
        if not forms and not endpoints:
            return []

        # Check for endpoints and Forms if not set False
        if not forms and not endpoints:
            return []

        ctx.runtime.util.status(f"\n[+] Running Dom XSS on discovered forms/endpoints...\n")
        domSessPool = []
        domSess = None
        try:
            domSessPool = ctx.runtime.auth.build_sessions(args.auth, args.username, args.password, args.start_url, args.login_path,
                                        desired_tasks=1,
                                        threads_per_sess=1,
                                        max_sess=1,
                                        pool_headroom=0
                                        )
            domSess = domSessPool[0] if domSessPool else None
        except Exception:
            log.debug("Session pool build failed", exc_info=True)

        try:
            bail = threading.Event() if args.bail_on_hit else None
            xss_dom_fuzzer = DomXSSFuzzer(
                baseUrl=args.start_url,
                headless=not args.no_headless,
                session=domSess,
                auth=args.auth,
                loginUsername=args.username,
                loginPassword=args.password,
                loginPath=args.login_path,
                token=runToken,
                bailEvent=bail,
                ctx=ctx.runtime
            )

            findings = xss_dom_fuzzer.run(ctx) or []
            return findings

        except Exception:
            log.debug("DOM phase failed", exc_info=True)
            return []

        finally:
            if domSessPool:
                for sess in domSessPool:
                    try:
                        sess.close()
                    except Exception:
                        log.debug("Session close failed (dom)", exc_info=True)