from urllib.parse import urlparse
from uuid import uuid4
import logging

from uni_fuzzer.core.fuzzer import PhaseContext
from uni_fuzzer.phases.endpoints import EndpointsPhase
from uni_fuzzer.phases.forms import FormsPhase
from uni_fuzzer.phases.dom import DomXSSPhase
from uni_fuzzer.core.logging_setup import setupLogging
from uni_fuzzer.crawler.crawler import Crawler
from uni_fuzzer.fuzzers.path import PathFuzzer
from uni_fuzzer.llm.semantic_llm import filterML
from uni_fuzzer.fuzzers.xss import XSSFuzzer
from uni_fuzzer.core.reporting import crawlerPrint, fuzzerPrint, crawlerJson, fuzzerJson
from uni_fuzzer.core.utility import get_cfg, isFuzzableField, collapseDuplicates, sortWordlist, getParents, status
cfg = get_cfg()

log = logging.getLogger(__name__)

def run(args):

    if args.log:
        setupLogging(
            level=args.log_level,
            logFile=args.log_file,
            toConsole=args.log_console,
            jsonMode=args.log_json,
            maxBytes=6_500_000,
            backUpCount=3)

    status("Starting run")

    if args.wordlist:
        args.wordlist = sortWordlist(args.wordlist)

    # Specific wordlists
    if args.pwordlist:
        pWordlist = sortWordlist(args.pwordlist)
    else:
        pWordlist = None

    if args.xwordlist:
        xWordlist = sortWordlist(args.xwordlist)
    else:
        xWordlist = None

    if args.swordlist:
        sWordlist = sortWordlist(args.swordlist)
    else:
        sWordlist = None

    # Checks if wordlist given or falls back to base
    wordlistPathsParams = pWordlist or args.wordlist
    wordlistXss = xWordlist or args.wordlist
    wordlistSqli = sWordlist or args.wordlist

    # if --llm is used wordlist needs to be provided
    if args.llm and not args.wordlist:
        status("[-] You must provide --wordlist when using --llm.")
        return

    # If using the llm takes the wordlist and filters it based on the prompt
    if args.llm:
        try:
            status(f"[+]Filtering wordlist using LLM prompt:'{args.llm}'")
            filtered = filterML(args.wordlist, args.llm, similarityThreshold=0.4)

            if not filtered:
                status("[-] No payloads matched the LLM prompt")
                return

            args.wordlist = filtered

            if not pWordlist:
                wordlistPathsParams = args.wordlist
            if not xWordlist:
                wordlistXss = args.wordlist
            if not sWordlist:
                wordlistSqli = args.wordlist

            status(f"[+] {len(filtered)} payloads remain after filtering.\n")

        except Exception:
            status("[!] Failed to apply LLM filtering")
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
            outputToFile=args.output_to_file,
            auth= args.auth,
            loginUsername = args.username,
            loginPassword = args.password,
            loginPath = args.login_path
        )


        endpoints, forms = crawler.crawl(args.start_url)

        crawlerPrint(endpoints, forms, output_to_file=args.output_to_file)
        if args.output_to_json:
            crawlerJson(endpoints, forms, output_to_json=True)
        return

    if args.use_crawler:

        allVulnerabilities = []
        runToken = f"XSSCanary-{uuid4().hex[:8]}"

        status("\n[+] Using crawler to discover endpoints and forms...")

        crawler = Crawler(
            mode= args.crawler_mode,
            maxPages= args.max_pages,
            rateLimit= args.rate_limit,
            headless=not args.no_headless,
            outputToFile= args.output_to_file,
            auth=args.auth,
            loginUsername=args.username,
            loginPassword=args.password,
            loginPath=args.login_path
        )
        endpoints, forms = crawler.crawl(args.start_url)

        crawlerPrint(endpoints, forms, output_to_file=args.output_to_file)
        if args.output_to_json:
            crawlerJson(endpoints, forms, output_to_json=True)

        rawDomForms = forms[:]

        forms = [
            f for f in forms
            if any(isFuzzableField(field) for field in f.get("formFields", []))
        ]

        if not endpoints and not forms:

            status("[-] No endpoints or forms found by crawler.")
            if not (args.xss_forms or args.xss_stored or args.xss_dom or args.fuzz_sqli or getattr(args, "all", False)):
                return

        # Derive base url for relative links
        parsed = urlparse(args.start_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        status(f"[+] Beginning fuzzing... \n")

        # Build shared context
        shared = {}
        ctx = PhaseContext(
            args=args,
            cfg=cfg,
            runToken=runToken,
            endpoints=endpoints,
            forms=forms if not (args.xss_dom or args.all) else rawDomForms,
            baseUrl=base,
            shared=shared,
            log=log
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
                phases.append(DomXSSPhase(wordlistXss=wordlistXss))
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
                phases.append(DomXSSPhase(wordlistXss=wordlistXss))

            return phases

        selected = seqPhases(args)

        if not selected:
            status("[-] No phases selected to run")
            return

        out = []
        for phase in selected:

            try:
                phase.prepare(ctx)
                out = phase.run(ctx) or []

            except Exception:
                log.debug("Phase failed", exc_info=True)
                out = []

            finally:
                try:
                    phase.teardown(ctx)
                except Exception:
                    log.debug("Phase teardown failed", exc_info=True)
            if out:
                allVulnerabilities.extend(out)

        allVulnerabilities = collapseDuplicates(allVulnerabilities)
        fuzzerPrint(allVulnerabilities, output_to_file=args.output_to_file)

        if args.output_to_json:
            fuzzerJson(allVulnerabilities, output_to_json=True)
        return

    # Fuzz a single target
    if args.xss_params:

        fuzzer = XSSFuzzer(
            baseUrl=args.start_url,
            useCrawler=False,
            wordlistPath=wordlistXss,
            outputToFile=args.output_to_file,
            headless=not args.no_headless,
            session=None,
            auth=args.auth,
            loginUsername=args.username,
            loginPassword=args.password,
            loginPath=args.login_path
        )

        results = fuzzer.paramXSS()
        allVulnerabilities = collapseDuplicates(results)
        fuzzerPrint(allVulnerabilities, output_to_file=args.output_to_file)
        if args.output_to_json:
            fuzzerJson(allVulnerabilities, output_to_json=True)

    else:

        fuzzer = PathFuzzer(
            baseUrl=args.start_url,
            wordlistPath=wordlistPathsParams,
            outputToFile=args.output_to_file,
            session=None,
            loginUsername=args.username,
            loginPassword=args.password,
            loginPath=args.login_path,
            auth=args.auth,
        )

        if args.fuzz_paths:
            for p in getParents(urlparse(args.start_url).path):
                fuzzer.fuzzPath(p)

        results = []

        if args.fuzz_params:
            results.extend(fuzzer.fuzzParams())

        results.extend(list(fuzzer.vulnerablePaths.values()))

        if args.report_all and getattr(fuzzer, "interesting200", None):
            results.extend(fuzzer.interesting200)
        if args.report_all and getattr(fuzzer, "interesting", None):
            results.extend(fuzzer.interesting)

        allVulnerabilities = collapseDuplicates(results)
        fuzzerPrint(allVulnerabilities, output_to_file=args.output_to_file)
        if args.output_to_json:
            fuzzerJson(allVulnerabilities, output_to_json=True)
