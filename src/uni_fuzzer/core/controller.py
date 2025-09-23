import threading
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import PurePosixPath
from uuid import uuid4
import logging

from uni_fuzzer.core.logging_setup import setupLogging
from uni_fuzzer.auth.auth import buildSessions
from uni_fuzzer.crawler.crawler import Crawler
from uni_fuzzer.fuzzers.path import PathFuzzer
from uni_fuzzer.llm.semantic_llm import filterML
from uni_fuzzer.fuzzers.xss import XSSFuzzer
from uni_fuzzer.fuzzers.sqli import SQLiFuzzer
from uni_fuzzer.core.reporting import crawlerPrint, fuzzerPrint, crawlerJson, fuzzerJson, Finding
from uni_fuzzer.core.utility import get_cfg, isFuzzableField, collapseDuplicates, sortWordlist, getDirectories, getParents, status
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

    else:

        if args.use_crawler:

            # Global storage to remove duplicate fuzzing
            globalVisitedPaths = set()
            globalVisitedFuzzPaths = set()
            globalVisitedLock = threading.Lock()

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

            if args.xss_dom or args.all:
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

            # Checks for fallback wordlist or specific
            if (args.fuzz_paths or args.fuzz_params or getattr(args, "all", False)) and not wordlistPathsParams:
                status("[-] Skipping path/param fuzzing: provide --pwordlist or --wordlist")

            if (args.xss_params or args.xss_forms or args.xss_stored or args.xss_dom or getattr(args, "all", False)) and not wordlistXss:
                status("[-] Skipping XSS fuzzing: provide --xwordlist or --wordlist")

            if (args.fuzz_sqli or args.fuzz_sqli_b or getattr(args, "all", False)) and not wordlistSqli:
                status("[-] Skipping SQLi fuzzing: provide --swordlist or --wordlist")

            def fuzzEndpoint(endpo, sess):
                """
                    To allow for parallel calls
                """

                results = []

                rawUrl = endpo["url"]
                params = endpo.get("params", [])
                fullUrl = rawUrl if rawUrl.startswith("http") else urljoin(base, rawUrl)

                if args.fuzz_paths:

                    # Path traversal fuzzing
                    status(f"[Thread] Path Fuzzing: {fullUrl}")
                    bail=threading.Event() if args.bail_on_hit else None

                    path_fuzzer = PathFuzzer(
                        baseUrl= fullUrl,
                        wordlistPath =wordlistPathsParams,
                        outputToFile= args.output_to_file,
                        session=sess,
                        auth=False,
                        bailEvent=bail
                    )
                    path_fuzzer.visitedPaths = globalVisitedPaths
                    path_fuzzer.visitedFuzzPaths = globalVisitedFuzzPaths
                    path_fuzzer.lock = globalVisitedLock

                    for path in getParents(urlparse(fullUrl).path):
                        path_fuzzer.fuzzPath(path)

                    if path_fuzzer.vulnerablePaths:
                        results.extend(list(path_fuzzer.vulnerablePaths.values()))


                    if args.report_all and getattr(path_fuzzer, "interesting200", None):
                        results.extend(path_fuzzer.interesting200)

                    if args.report_all and getattr(path_fuzzer, "interesting", None):
                        results.extend(path_fuzzer.interesting)

                if args.fuzz_params and params:

                    # Param fuzzing
                    fuzzQuery = "&".join([f"{p}=FUZZ" for p in params])
                    fuzzedUrl = f"{fullUrl}?{fuzzQuery}" if "?" not in fullUrl else f"{fullUrl}&{fuzzQuery}"

                    status(f"[Thread] Param Fuzzing: {fuzzedUrl}")
                    bail = threading.Event() if args.bail_on_hit else None

                    param_fuzzer = PathFuzzer(
                        baseUrl= fuzzedUrl,
                        wordlistPath= wordlistPathsParams,
                        outputToFile= args.output_to_file,
                        session=sess,
                        auth=False,
                        bailEvent=bail
                    )
                    param_fuzzer.visitedPaths = globalVisitedPaths
                    param_fuzzer.visitedFuzzPaths = globalVisitedFuzzPaths
                    param_fuzzer.lock = globalVisitedLock

                    res = param_fuzzer.fuzzParams()
                    if res:
                        results.extend(res)

                if args.xss_params and params:

                    # XSS fuzzing via params
                    fuzzQuery = "&".join([f"{p}=FUZZ" for p in params])
                    fuzzedUrl = f"{fullUrl}?{fuzzQuery}" if "?" not in fullUrl else f"{fullUrl}&{fuzzQuery}"

                    status(f"[Thread] XSS Param Fuzzing: {fuzzedUrl}")
                    bail = threading.Event() if args.bail_on_hit else None

                    xss_param_fuzzer = XSSFuzzer(
                        baseUrl= fuzzedUrl,
                        useCrawler=False,
                        wordlistPath=wordlistXss,
                        outputToFile=args.output_to_file,
                        headless=not args.no_headless,
                        session=sess,
                        auth=False,
                        token=runToken,
                        bailEvent=bail
                    )

                    res = xss_param_fuzzer.paramXSS()

                    if res:
                        results.extend(res)

                return results

            def fuzzForm(form, sess):

                results = []

                fullUrl = form.get("url")
                if fullUrl and not fullUrl.startswith("http"):
                    fullUrl = urljoin(base, fullUrl)

                if args.xss_forms:

                    status(f"[Thread] XSS Form Fuzzing: {fullUrl}")
                    bail = threading.Event() if args.bail_on_hit else None
                    xss_form_fuzzer = XSSFuzzer(
                        baseUrl=fullUrl,
                        useCrawler=False,
                        wordlistPath=wordlistXss,
                        outputToFile=args.output_to_file,
                        headless=not args.no_headless,
                        session=sess,
                        auth=False,
                        token=runToken,
                        bailEvent=bail
                    )

                    res = xss_form_fuzzer.formXSS([form])

                    if res:

                        results.extend(res)

                if args.xss_stored:

                    status(f"[Thread] XSS Stored Fuzzing: {fullUrl}")
                    bail = threading.Event() if args.bail_on_hit else None
                    xss_stored_fuzzer = XSSFuzzer(
                        baseUrl=fullUrl,
                        useCrawler= False,
                        wordlistPath=wordlistXss,
                        outputToFile=args.output_to_file,
                        headless=not args.no_headless,
                        session=sess,
                        auth=False,
                        loginUsername=args.username,
                        loginPassword=args.password,
                        loginPath=args.login_path,
                        token=runToken,
                        bailEvent=bail
                    )

                    # Pass directories of forms/ shared directory endpoints
                    formDir = getDirectories(urlparse(fullUrl).path)
                    relevantEndpoints = [
                        endp["url"] if endp["url"].startswith("http") else urljoin(base, endp["url"])
                        for endp in endpoints
                        if getDirectories(urlparse(endp["url"]).path) == formDir
                    ]

                    res = xss_stored_fuzzer.storedXSS([form], endpoints=relevantEndpoints)

                    if res:

                        results.extend(res)

                if args.fuzz_sqli:

                    status(f"[Thread] SQLi Form Fuzzing: {fullUrl}")
                    bail = threading.Event() if args.bail_on_hit else None
                    sqli_form_fuzzer = SQLiFuzzer(
                        baseUrl=args.start_url,
                        useCrawler= False,
                        wordlistPath=wordlistSqli,
                        outputToFile=args.output_to_file,
                        session=sess,
                        auth=False,
                        bailEvent=bail
                    )

                    res = sqli_form_fuzzer.SQLiFuzz([form])

                    if res:
                        results.extend(res if args.report_all else [v for v in res if v.type != "sqli_potential"])

                if args.fuzz_sqli_b:

                    status(f"[Thread] SQLi Blind Form Fuzzing: {fullUrl}")
                    bail = threading.Event() if args.bail_on_hit else None
                    sqli_blind_fuzzer = SQLiFuzzer(
                        baseUrl=args.start_url,
                        useCrawler=False,
                        wordlistPath=wordlistSqli,
                        outputToFile=args.output_to_file,
                        session=sess,
                        auth=False,
                        bailEvent=bail
                    )

                    res = sqli_blind_fuzzer.SQLiBlindFuzz([form])

                    if res:
                        results.extend(res)

                return results

            def runPhase():

                # Check for wordlists if not set False
                if (args.fuzz_paths or args.fuzz_params) and not wordlistPathsParams:
                    return
                if (args.xss_params or args.xss_forms or args.xss_stored or args.xss_dom) and not wordlistXss:
                    return
                if (args.fuzz_sqli or args.fuzz_sqli_b) and not wordlistSqli:
                    return
                # Build the endpoint list
                if args.fuzz_paths:
                    uniqueUrl = {}

                    for enp in endpoints:
                        parsedPat = urlparse(enp["url"]).path or "/"
                        baseDire = str(PurePosixPath(getDirectories(parsedPat))).rstrip("/")

                        if baseDire not in uniqueUrl:
                            uniqueUrl[baseDire] = enp
                    phaseEndpoints = list(uniqueUrl.values())
                else:
                    phaseEndpoints = endpoints

                # Update visited
                for epoi in phaseEndpoints:
                    pa = urlparse(epoi["url"]).path or "/"
                    di = getDirectories(pa)
                    globalVisitedPaths.add(di)

                if args.fuzz_paths or args.fuzz_params or args.xss_params:
                    status(f"\n[+] Starting threaded fuzzing on discovered endpoints... \n")
                    sessPool = buildSessions(args.auth, args.username, args.password, args.start_url, args.login_path,
                                             desiredTasks=len(phaseEndpoints),
                                             threadsPerSess=cfg["concurrency"]["threads_per_session"],
                                             maxSess=cfg["concurrency"].get("max_sessions_cap", None),
                                             poolHeadroom=0.25
                                             )
                    log.debug("Session pool size=%d (phase=endpoints)", len(sessPool))
                    try:
                        with ThreadPoolExecutor(max_workers=min(len(phaseEndpoints), cfg["concurrency"]["max_workers"])) as executor:
                            # Run fuzzer using threads across all endpoints assigning a session from the session pool
                            futures = []
                            for i, epo in enumerate(phaseEndpoints):
                                sess = sessPool[i % len(sessPool)]
                                futures.append(executor.submit(fuzzEndpoint, epo, sess))

                            for future in as_completed(futures):
                                try:
                                    resu = future.result()
                                except Exception:
                                    log.debug("Endpoint future failed", exc_info=True)
                                    continue
                                if resu:
                                    allVulnerabilities.extend(resu)
                    # Close sessions and delete the pool
                    finally:
                        for sess in sessPool:
                            try:
                                sess.close()
                            except Exception:
                                log.debug("Session close failed", exc_info=True)
                        del sessPool

                if args.xss_forms or args.xss_stored or args.fuzz_sqli or args.fuzz_sqli_b:
                    status(f"\n[+] Starting threaded fuzzing on discovered Forms... \n")
                    sessPool = buildSessions(args.auth, args.username, args.password, args.start_url, args.login_path,
                                             desiredTasks=len(forms),
                                             threadsPerSess=cfg["concurrency"]["threads_per_session"],
                                             maxSess=cfg["concurrency"].get("max_sessions_cap", None),
                                             poolHeadroom=0.25
                                             )
                    log.debug("Session pool size=%d (phase=endpoints)", len(sessPool))
                    try:
                        with ThreadPoolExecutor(max_workers=min(len(forms), cfg["concurrency"]["max_workers"])) as executor:
                            # Run fuzzer using threads across all forms assigning a session from the session pool
                            futures = []
                            for i, form in enumerate(forms):
                                sess = sessPool[i % len(sessPool)]
                                futures.append(executor.submit(fuzzForm, form, sess))

                            for future in as_completed(futures):
                                try:
                                    res = future.result()
                                except Exception:
                                    log.debug("Form future failed", exc_info=True)
                                    continue
                                if res:
                                    allVulnerabilities.extend(res)
                    # Close sessions and delete the pool
                    finally:
                        for sess in sessPool:
                            try:
                                sess.close()
                            except Exception:
                                log.debug("Session close failed", exc_info=True)
                        del sessPool

                if args.xss_dom:
                    status(f"\n[+] Running Dom XSS on discovered forms/endpoints...\n")
                    domSessPool = buildSessions(args.auth, args.username, args.password, args.start_url, args.login_path,
                                                desiredTasks=1,
                                                threadsPerSess=1,
                                                maxSess=1,
                                                poolHeadroom=0
                                                )
                    domSess = domSessPool[0] if domSessPool else None
                    try:
                        bail = threading.Event() if args.bail_on_hit else None
                        xss_dom_fuzzer = XSSFuzzer(
                            baseUrl=args.start_url,
                            useCrawler=False,
                            wordlistPath=wordlistXss,
                            outputToFile=args.output_to_file,
                            headless=not args.no_headless,
                            session=domSess,
                            auth=args.auth,
                            loginUsername=args.username,
                            loginPassword=args.password,
                            loginPath=args.login_path,
                            token=runToken,
                            bailEvent=bail
                        )

                        res = xss_dom_fuzzer.domXSS(forms=rawDomForms, endpoints=endpoints)

                        allVulnerabilities.extend(res)
                    finally:
                        for sess in domSessPool:
                            try:
                                sess.close()
                            except Exception:
                                log.debug("Session close failed (dom)", exc_info=True)

            # Sequential run for --all
            if getattr(args, "all", False):

                # SQLi blind
                args.fuzz_sqli_b = True
                args.fuzz_sqli = args.xss_params = args.xss_forms = args.xss_stored = args.xss_dom = args.fuzz_paths = args.fuzz_params = False
                runPhase()

                # SQLi content
                args.fuzz_sqli = True
                args.fuzz_sqli_b = args.xss_params = args.xss_forms = args.xss_stored = args.xss_dom = args.fuzz_paths = args.fuzz_params = False
                runPhase()

                # XSS params
                args.xss_params = True
                args.fuzz_sqli = args.fuzz_sqli_b = args.xss_forms = args.xss_stored = args.xss_dom = args.fuzz_paths = args.fuzz_params = False
                runPhase()

                # XSS forms
                args.xss_forms = True
                args.fuzz_sqli = args.fuzz_sqli_b = args.xss_params = args.xss_stored = args.xss_dom = args.fuzz_paths = args.fuzz_params = False
                runPhase()

                # XSS DOM
                args.xss_dom = True
                args.fuzz_sqli = args.fuzz_sqli_b = args.xss_params = args.xss_forms = args.xss_stored = args.fuzz_paths = args.fuzz_params = False
                runPhase()

                # XSS Stored
                args.xss_stored = True
                args.fuzz_sqli = args.fuzz_sqli_b = args.xss_params = args.xss_forms = args.xss_dom = args.fuzz_paths = args.fuzz_params = False
                runPhase()

                # Path traversal
                args.fuzz_paths = True
                args.fuzz_params = args.xss_params = args.xss_forms = args.xss_stored = args.xss_dom = args.fuzz_sqli = args.fuzz_sqli_b = False
                runPhase()

                # Param fuzzing
                args.fuzz_params = True
                args.fuzz_paths = args.xss_params = args.xss_forms = args.xss_stored = args.xss_dom = args.fuzz_sqli = args.fuzz_sqli_b = False
                runPhase()

            # Or run normally
            else:
                runPhase()

            allVulnerabilities = collapseDuplicates(allVulnerabilities)
            fuzzerPrint(allVulnerabilities, output_to_file=args.output_to_file)
            if args.output_to_json:
                fuzzerJson(allVulnerabilities, output_to_json=True)


        else:
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
