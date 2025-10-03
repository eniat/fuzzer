import threading
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
from uuid import uuid4

from uni_fuzzer.core.fuzzer_phases import FuzzerPhase, PhaseContext
from uni_fuzzer.core.utility import status, getDirectories
from uni_fuzzer.auth.auth import buildSessions
from uni_fuzzer.fuzzers.xss_stored import StoredXSSFuzzer
from uni_fuzzer.fuzzers.xss_form import FormXSSFuzzer
from uni_fuzzer.fuzzers.sql_inj import InjSQLFuzzer
from uni_fuzzer.fuzzers.sql_iblind import BlindSQLiFuzzer

log = logging.getLogger(__name__)

class FormsPhase (FuzzerPhase):
    """
        Runs the forms fuzzer/s depending on args
    """

    def __init__(self, run_xss_forms, run_xss_stored, run_sqli, run_sqli_b, wordlistXss, wordlistSqli):
        self.run_xss_forms = run_xss_forms
        self.run_xss_stored = run_xss_stored
        self.run_sqli = run_sqli
        self.run_sqli_b = run_sqli_b
        self.wordlistXss = wordlistXss
        self.wordlistSqli = wordlistSqli

    @property
    def name(self):
        return "Forms"


    def run(self, ctx:PhaseContext):
        """
            Dor the running of the Forms Phase
        """
        args = ctx.args
        cfg = ctx.cfg
        base = ctx.baseUrl
        endpoints = ctx.endpoints
        forms = ctx.forms or []
        allVulns= []

        # Check for wordlists and Forms if not set False
        if (self.run_xss_forms or self.run_xss_stored) and not self.wordlistXss:
            return []
        if self.run_sqli and not self.wordlistSqli:
            return []
        if not forms:
            return []

        def fuzzForm(form, sess):
            """
                To allow for parallel calls
            """

            results = []

            fullUrl = form.get("url")

            if not fullUrl:
                log.debug("Form missing URL: %s", form.get("name") or "<no-name>")
                return []

            if  not fullUrl.startswith("http"):
                fullUrl = urljoin(base, fullUrl)

            if self.run_xss_forms:
                runToken = f"XSSCanary-{uuid4().hex[:8]}"

                status(f"[Thread] XSS Form Fuzzing: {fullUrl}")
                bail = threading.Event() if args.bail_on_hit else None
                xss_form_fuzzer = FormXSSFuzzer(
                    baseUrl=fullUrl,
                    wordlistPath=self.wordlistXss,
                    session=sess,
                    auth=False,
                    token=runToken,
                    bailEvent=bail
                )

                res = xss_form_fuzzer.run({"forms": [form]})

                if res:
                    results.extend(res)

            if self.run_xss_stored:
                runToken = f"XSSCanary-{uuid4().hex[:8]}"

                status(f"[Thread] XSS Stored Fuzzing: {fullUrl}")
                bail = threading.Event() if args.bail_on_hit else None
                xss_stored_fuzzer = StoredXSSFuzzer(
                    baseUrl=fullUrl,
                    wordlistPath=self.wordlistXss,
                    session=sess,
                    auth=False,
                    token=runToken,
                    bailEvent=bail
                )

                res = xss_stored_fuzzer.run({"forms": [form]})

                if res:
                    results.extend(res)

            if self.run_sqli:

                status(f"[Thread] SQLi Form Fuzzing: {fullUrl}")
                bail = threading.Event() if args.bail_on_hit else None
                sqli_form_fuzzer = InjSQLFuzzer(
                    baseUrl=fullUrl,
                    wordlistPath=self.wordlistSqli,
                    session=sess,
                    auth=False,
                    bailEvent=bail
                )

                res = sqli_form_fuzzer.run({"forms": [form]})

                if res:
                    results.extend(res if args.report_all else [v for v in res if v.type != "sqli_potential"])

            if self.run_sqli_b:

                status(f"[Thread] SQLi Blind Form Fuzzing: {fullUrl}")
                bail = threading.Event() if args.bail_on_hit else None
                sqli_blind_fuzzer = BlindSQLiFuzzer(
                    baseUrl=fullUrl,
                    wordlistPath=self.wordlistSqli,
                    session=sess,
                    auth=False,
                    bailEvent=bail
                )

                res = sqli_blind_fuzzer.run({"forms": [form]})

                if res:
                    results.extend(res)

            return results

        status(f"\n[+] Starting threaded fuzzing on discovered Forms... \n")
        sessPool = []
        try:
            sessPool = buildSessions(args.auth, args.username, args.password, args.start_url, args.login_path,
                                     desiredTasks=len(forms),
                                     threadsPerSess=cfg["concurrency"]["threads_per_session"],
                                     maxSess=cfg["concurrency"].get("max_sessions_cap", None),
                                     poolHeadroom=0.25
                                     )
            log.debug("Session pool size=%d (phase=forms)", len(sessPool))
        except Exception:
            log.debug("Session pool build failed", exc_info=True)


        try:
            with ThreadPoolExecutor(max_workers=min(len(forms), cfg["concurrency"]["max_workers"])) as executor:
                # Run fuzzer using threads across all forms assigning a session from the session pool
                futures = []
                for i, form in enumerate(forms):
                    sess = sessPool[i % len(sessPool)] if sessPool else None
                    futures.append(executor.submit(fuzzForm, form, sess))

                for future in as_completed(futures):
                    try:
                        res = future.result()
                    except Exception:
                        log.debug("Form future failed", exc_info=True)
                        continue
                    if res:
                        allVulns.extend(res)
        # Close sessions and delete the pool
        finally:
            if sessPool:
                for sess in sessPool:
                    try:
                        sess.close()
                    except Exception:
                        log.debug("Session close failed", exc_info=True)
                del sessPool

        return allVulns