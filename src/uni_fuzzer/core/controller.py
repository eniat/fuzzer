import logging

from urllib.parse import urlparse

from ..crawler.crawler import Crawler
from ..fuzzers.path_traversal import TraversalPathFuzzer
from ..fuzzers.path_param import ParamPathFuzzer
from ..llm.semantic_llm import filterML
from ..fuzzers.xss_param import ParamXSSFuzzer
from ..core.reporting import crawlerPrint, fuzzerPrint, crawlerJson, fuzzerJson

from ..core.utility import get_cfg
from ..adapters.auth_default import DefaultAuth
from ..adapters.util_default import DefaultUtil
from ..adapters.base_default import DefaultBase
from ..adapters.dete_default import DefaultDete
from ..adapters.prob_default import DefaultProb
from ..runtime.context import AppContext
from ..phases.fuzzer_phases import PhaseContext
from ..phases.endpoints import EndpointsPhase
from ..phases.forms import FormsPhase
from ..phases.dom import DomXSSPhase
from ..runtime.logging_setup import setupLogging

log = logging.getLogger(__name__)

def build_ctx(args) -> AppContext:
    util = DefaultUtil()
    return AppContext(auth=DefaultAuth(util=util),
                      util=util,dete=DefaultDete(),
                      base=DefaultBase(),
                      prob=DefaultProb(),
                      cfg= get_cfg(),args=args)

def run(args):
    appCtx = build_ctx(args)

    if args.log:
        setupLogging(
            level=args.log_level,
            logFile=args.log_file,
            toConsole=args.log_console,
            jsonMode=args.log_json,
            maxBytes=6_500_000,
            backUpCount=3)

    appCtx.util.status("Starting run")

    if args.wordlist:
        args.wordlist = appCtx.util.sort_wordlist(args.wordlist)

    # Specific wordlists
    pWordlist = appCtx.util.sort_wordlist(args.pwordlist) if args.pwordlist else None
    xWordlist = appCtx.util.sort_wordlist(args.xwordlist) if args.xwordlist else None
    sWordlist = appCtx.util.sort_wordlist(args.swordlist) if args.swordlist else None

    # Checks if wordlist given or falls back to base
    wordlistPathsParams = pWordlist or args.wordlist
    wordlistXss = xWordlist or args.wordlist
    wordlistSqli = sWordlist or args.wordlist

    # if --llm is used wordlist needs to be provided
    if args.llm and not args.wordlist:
        appCtx.util.status("[-] You must provide --wordlist when using --llm.")
        return

    # If using the llm takes the wordlist and filters it based on the prompt
    if args.llm:
        try:
            appCtx.util.status(f"[+]Filtering wordlist using LLM prompt:'{args.llm}'")
            filtered = filterML(args.wordlist, args.llm, similarityThreshold=0.4, util=appCtx.util)

            if not filtered:
                appCtx.util.status("[-] No payloads matched the LLM prompt")
                return

            args.wordlist = filtered

            if not pWordlist:
                wordlistPathsParams = args.wordlist
            if not xWordlist:
                wordlistXss = args.wordlist
            if not sWordlist:
                wordlistSqli = args.wordlist

            appCtx.util.status(f"[+] {len(filtered)} payloads remain after filtering.\n")

        except Exception:
            appCtx.util.status("[!] Failed to apply LLM filtering")
            log.debug("Failed to apply LLM filtering", exc_info=True)
            return

    # If no fuzzer selected run crawler on its own
    if (not args.fuzz_paths
            and not args.fuzz_params
            and not args.xss_params
            and not args.xss_forms
            and not args.xss_stored
            and not args.xss_dom
            and not args.fuzz_sqli
            and not args.fuzz_sqli_b
            and not getattr(args, "all", False)):

        crawler = Crawler(
            mode=args.crawler_mode,
            maxPages=args.max_pages,
            rateLimit=args.rate_limit,
            headless= not args.no_headless,
            auth= args.auth,
            loginUsername = args.username,
            loginPassword = args.password,
            loginPath = args.login_path,
            ctx=appCtx
        )


        endpoints, forms = crawler.crawl(args.start_url)

        crawlerPrint(endpoints, forms, output_to_file=args.output_to_file)
        if args.output_to_json:
            crawlerJson(endpoints, forms, output_to_json=True)
        return

    if args.use_crawler:

        allVulnerabilities = []

        appCtx.util.status("\n[+] Using crawler to discover endpoints and forms...")

        crawler = Crawler(
            mode= args.crawler_mode,
            maxPages= args.max_pages,
            rateLimit= args.rate_limit,
            headless=not args.no_headless,
            auth=args.auth,
            loginUsername=args.username,
            loginPassword=args.password,
            loginPath=args.login_path,
            ctx=appCtx
        )
        endpoints, forms = crawler.crawl(args.start_url)

        crawlerPrint(endpoints, forms, output_to_file=args.output_to_file)
        if args.output_to_json:
            crawlerJson(endpoints, forms, output_to_json=True)

        rawForms = forms[:]

        filteredForms  = [
            f for f in forms
            if any(appCtx.util.is_fuzzable_field(field) for field in f.get("formFields", []))
        ]

        if not endpoints and not forms:

            appCtx.util.status("[-] No endpoints or forms found by crawler.")
            if not (args.xss_forms or args.xss_stored or args.xss_dom or args.fuzz_sqli or getattr(args, "all", False)):
                return

        # Derive base url for relative links
        parsed = urlparse(args.start_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        appCtx.util.status(f"[+] Beginning fuzzing... \n")

        # Build shared context
        shared = {}
        phaseCtx = PhaseContext(
            args=args,
            cfg=appCtx.cfg,
            endpoints=endpoints,
            forms=filteredForms,
            rawForms=rawForms,
            baseUrl=base,
            shared=shared,
            log=log,
            runtime= appCtx
        )

        def seqPhases(arg):

            phases= []

            # Sequential run for --all
            if getattr(arg, "all", False):

                # SQLi blind
                phases.append(FormsPhase(run_xss_forms=False, run_xss_stored=False, run_sqli=False, run_sqli_b=True, wordlistXss=wordlistXss, wordlistSqli=wordlistSqli))
                # SQLi content
                phases.append(FormsPhase(run_xss_forms=False, run_xss_stored=False, run_sqli=True, run_sqli_b=False, wordlistXss=wordlistXss, wordlistSqli=wordlistSqli))
                # XSS params
                phases.append(EndpointsPhase(run_paths=False, run_params=False, run_xss_params=True, wordlistPathsParams=wordlistPathsParams, wordlistXss=wordlistXss))
                # XSS forms
                phases.append(FormsPhase(run_xss_forms=True, run_xss_stored=False, run_sqli=False, run_sqli_b=False, wordlistXss=wordlistXss, wordlistSqli=wordlistSqli))
                # XSS DOM
                phases.append(DomXSSPhase())
                # XSS Stored
                phases.append(FormsPhase(run_xss_forms=False, run_xss_stored=True, run_sqli=False, run_sqli_b=False, wordlistXss=wordlistXss, wordlistSqli=wordlistSqli))
                # Path traversal
                phases.append(EndpointsPhase(run_paths=True, run_params=False, run_xss_params=False,wordlistPathsParams=wordlistPathsParams, wordlistXss=wordlistXss))
                # Param fuzzing
                phases.append(EndpointsPhase(run_paths=False, run_params=True, run_xss_params=False, wordlistPathsParams=wordlistPathsParams, wordlistXss=wordlistXss))

                return phases

            # Or run only selected
            if arg.fuzz_paths or arg.fuzz_params or arg.xss_params:
                phases.append(EndpointsPhase(
                    run_paths=arg.fuzz_paths,
                    run_params=arg.fuzz_params,
                    run_xss_params=arg.xss_params,
                    wordlistPathsParams=wordlistPathsParams,
                    wordlistXss=wordlistXss
                ))

            if arg.xss_forms or arg.xss_stored or arg.fuzz_sqli or arg.fuzz_sqli_b:
                phases.append(FormsPhase(
                    run_xss_forms=arg.xss_forms,
                    run_xss_stored=arg.xss_stored,
                    run_sqli=arg.fuzz_sqli,
                    run_sqli_b=arg.fuzz_sqli_b,
                    wordlistXss=wordlistXss,
                    wordlistSqli=wordlistSqli
                ))

            if arg.xss_dom:
                phases.append(DomXSSPhase())

            return phases

        selected = seqPhases(args)

        if not selected:
            appCtx.util.status("[-] No phases selected to run")
            return

        out = []
        for phase in selected:

            try:
                phase.prepare(phaseCtx)
                out = phase.run(phaseCtx) or []

            except Exception:
                log.debug("Phase failed", exc_info=True)
                out = []

            finally:
                try:
                    phase.teardown(phaseCtx)
                except Exception:
                    log.debug("Phase teardown failed", exc_info=True)
            if out:
                allVulnerabilities.extend(out)

        allVulnerabilities = appCtx.util.collapse_duplicates(allVulnerabilities)
        fuzzerPrint(allVulnerabilities, output_to_file=args.output_to_file)

        if args.output_to_json:
            fuzzerJson(allVulnerabilities, output_to_json=True)
        return

    # Fuzz a single target
    if args.xss_params:

        fuzzer = ParamXSSFuzzer(
            baseUrl=args.start_url,
            wordlistPath=wordlistXss,
            session=None,
            auth=args.auth,
            loginUsername=args.username,
            loginPassword=args.password,
            loginPath=args.login_path,
            ctx=appCtx
        )

        results = fuzzer.run()
        allVulnerabilities = appCtx.util.collapse_duplicates(results)
        fuzzerPrint(allVulnerabilities, output_to_file=args.output_to_file)
        if args.output_to_json:
            fuzzerJson(allVulnerabilities, output_to_json=True)
        return

    results = []

    if args.fuzz_paths:
        fuzzer = TraversalPathFuzzer(
            baseUrl=args.start_url,
            wordlistPath=wordlistPathsParams,
            session=None,
            loginUsername=args.username,
            loginPassword=args.password,
            loginPath=args.login_path,
            auth=args.auth,
            ctx = appCtx
        )

        for p in appCtx.util.get_parents(urlparse(args.start_url).path):
            res = fuzzer.run(path=p) or []
            results.extend(res)

        if args.report_all and getattr(fuzzer, "interesting200", None):
            results.extend(fuzzer.interesting200)
        if args.report_all and getattr(fuzzer, "interesting", None):
            results.extend(fuzzer.interesting)

    if args.fuzz_params:
        fuzzer = ParamPathFuzzer(
            baseUrl=args.start_url,
            wordlistPath=wordlistPathsParams,
            session=None,
            auth=args.auth,
            loginUsername=args.username,
            loginPassword=args.password,
            loginPath=args.login_path,
            ctx=appCtx
        )
        res = fuzzer.run() or []
        results.extend(res)

    allVulnerabilities = appCtx.util.collapse_duplicates(results)
    fuzzerPrint(allVulnerabilities, output_to_file=args.output_to_file)
    if args.output_to_json:
        fuzzerJson(allVulnerabilities, output_to_json=True)
