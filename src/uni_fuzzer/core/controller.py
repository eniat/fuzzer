import threading
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import PurePosixPath
from uuid import uuid4

from uni_fuzzer.auth.auth import buildSessions
from uni_fuzzer.crawler.crawler import Crawler
from uni_fuzzer.fuzzers.path import PathFuzzer
from uni_fuzzer.llm.semantic_llm import filterML
from uni_fuzzer.fuzzers.xss import XSSFuzzer
from uni_fuzzer.fuzzers.sqli import SQLiFuzzer
from uni_fuzzer.core.reporting import crawlerPrint, fuzzerPrint
from uni_fuzzer.core.utility import get_cfg, isFuzzableField, collapseDuplicates, sortWordlist, getDirectories, getParents
cfg = get_cfg()


def run(args):

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
        print("[-] You must provide --wordlist when using --llm.")
        return

    # If using the llm takes the wordlist and filters it based on the prompt
    if args.llm:
        try:

            print(f"[+]Filtering wordlist using LLM prompt:'{args.llm}'")
            filtered = filterML(args.wordlist, args.llm, similarityThreshold=0.4)

            if not filtered:
                print("[-] No payloads matched the LLM prompt")
                return

            args.wordlist = filtered

            if not pWordlist:
                wordlistPathsParams = args.wordlist
            if not xWordlist:
                wordlistXss = args.wordlist
            if not sWordlist:
                wordlistSqli = args.wordlist

            # For debugging of the LLM
            # print("[+] Matched payloads:")
            # for p in filtered:
            #     print(f"   {p}")

            print(f"[+] {len(filtered)} payloads remain after filtering.\n")

        except Exception as e:
            print(f"[!] Failed to apply LLM filtering: {e}")
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

        crawlerPrint(endpoints, forms, output_to_file=args.output_to_file, filename="CrawlerOutput.txt")

    else:

        if args.use_crawler:

            # Global storage to remove duplicate fuzzing
            globalVisitedPaths = set()
            globalVisitedFuzzPaths = set()

            allVulnerabilities = []
            runToken = f"XSSCanary-{uuid4().hex[:8]}"

            print("\n[+] Using crawler to discover endpoints and forms...")

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

            crawlerPrint(endpoints, forms, output_to_file=args.output_to_file, filename="CrawlerOutput.txt")

            rawDomForms = forms[:]

            forms = [
                f for f in forms
                if any(isFuzzableField(field) for field in f.get("formFields", []))
            ]

            if not endpoints and not forms:

                print("[-] No endpoints or forms found by crawler.")
                if not (args.xss_forms or args.xss_stored or args.xss_dom or args.fuzz_sqli or getattr(args, "all", False)):
                    return

            # Derive base url for relative links
            parsed = urlparse(args.start_url)
            base = f"{parsed.scheme}://{parsed.netloc}"

            if args.fuzz_paths:
                # Filter to unique base directories
                uniqueUrls = {}
                for ep in endpoints:
                    parsedPath = urlparse(ep["url"]).path or "/"
                    baseDir = str(PurePosixPath(getDirectories(parsedPath))).rstrip("/")

                    if baseDir not in uniqueUrls:
                        uniqueUrls[baseDir] = ep
                UniqueEndpoints = list(uniqueUrls.values())

            else:
                UniqueEndpoints = endpoints

            #  Add to visited directories
            for ep in UniqueEndpoints:
                p = urlparse(ep["url"]).path or "/"
                d = getDirectories(p)
                globalVisitedPaths.add(d)

            print(f"[+] Beginning fuzzing... \n")

            # Checks for fallback wordlist or specific
            if (args.fuzz_paths or args.fuzz_params or getattr(args, "all", False)) and not wordlistPathsParams:
                print("[-] Skipping path/param fuzzing: provide --pwordlist or --wordlist")

            if (args.xss_params or args.xss_forms or args.xss_stored or args.xss_dom or getattr(args, "all", False)) and not wordlistXss:
                print("[-] Skipping XSS fuzzing: provide --xwordlist or --wordlist")

            if (args.fuzz_sqli or args.fuzz_sqli_b or getattr(args, "all", False)) and not wordlistSqli:
                print("[-] Skipping SQLi fuzzing: provide --swordlist or --wordlist")

            def fuzzEndpoint(ep, sess):
                """
                    To allow for parallel calls
                """

                results = []

                rawUrl = ep["url"]
                params = ep.get("params", [])
                fullUrl = rawUrl if rawUrl.startswith("http") else urljoin(base, rawUrl)

                if args.fuzz_paths:

                    # Path traversal fuzzing
                    print(f"[Thread] Path Fuzzing: {fullUrl}")
                    bail=threading.Event() if args.bail_on_hit else None

                    fuzzer = PathFuzzer(
                        baseUrl= fullUrl,
                        wordlistPath =wordlistPathsParams,
                        outputToFile= args.output_to_file,
                        session=sess,
                        auth=False,
                        bailEvent=bail
                    )
                    fuzzer.visitedPaths = globalVisitedPaths
                    fuzzer.visitedFuzzPaths = globalVisitedFuzzPaths

                    for path in getParents(fullUrl):
                        fuzzer.fuzzPath(path)

                    if fuzzer.vulnerablePaths:
                        results.extend(list(fuzzer.vulnerablePaths.values()))


                    if args.report_all and getattr(fuzzer, "interesting200", None):
                        results.extend(fuzzer.interesting200)

                    if args.report_all and getattr(fuzzer, "interesting", None):
                        results.extend(fuzzer.interesting)

                if args.fuzz_params and params:

                    # Param fuzzing
                    fuzzQuery = "&".join([f"{p}=FUZZ" for p in params])
                    fuzzedUrl = f"{fullUrl}?{fuzzQuery}" if "?" not in fullUrl else f"{fullUrl}&{fuzzQuery}"

                    print(f"[Thread] Param Fuzzing: {fuzzedUrl}")
                    bail = threading.Event() if args.bail_on_hit else None

                    fuzzer = PathFuzzer(
                        baseUrl= fuzzedUrl,
                        wordlistPath= wordlistPathsParams,
                        outputToFile= args.output_to_file,
                        session=sess,
                        auth=False,
                        bailEvent=bail
                    )
                    fuzzer.visitedPaths = globalVisitedPaths
                    fuzzer.visitedFuzzPaths = globalVisitedFuzzPaths

                    res = fuzzer.fuzzParams()
                    if res:
                        results.extend(res)

                if args.xss_params and params:

                    # XSS fuzzing via params
                    fuzzQuery = "&".join([f"{p}=FUZZ" for p in params])
                    fuzzedUrl = f"{fullUrl}?{fuzzQuery}" if "?" not in fullUrl else f"{fullUrl}&{fuzzQuery}"

                    print(f"[Thread] XSS Param Fuzzing: {fuzzedUrl}")
                    bail = threading.Event() if args.bail_on_hit else None

                    fuzzer = XSSFuzzer(
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

                    res = fuzzer.paramXSS()

                    if res:
                        results.extend(res)

                return results

            def fuzzForm(form, sess):

                results = []

                fullUrl = form.get("url")
                if fullUrl and not fullUrl.startswith("http"):
                    fullUrl = urljoin(base, fullUrl)

                if args.xss_forms:

                    print(f"[Thread] XSS Form Fuzzing: {fullUrl}")
                    bail = threading.Event() if args.bail_on_hit else None
                    fuzzer = XSSFuzzer(
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

                    res = fuzzer.formXSS([form])

                    if res:

                        results.extend(res)

                if args.xss_stored:

                    print(f"[Thread] XSS Stored Fuzzing: {fullUrl}")
                    bail = threading.Event() if args.bail_on_hit else None
                    fuzzer = XSSFuzzer(
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
                        ep["url"] if ep["url"].startswith("http") else urljoin(base, ep["url"])
                        for ep in endpoints
                        if getDirectories(urlparse(ep["url"]).path) == formDir
                    ]

                    res = fuzzer.storedXSS([form], endpoints=relevantEndpoints)

                    if res:

                        results.extend(res)

                if args.fuzz_sqli:

                    print(f"[Thread] SQLi Form Fuzzing: {fullUrl}")
                    bail = threading.Event() if args.bail_on_hit else None
                    fuzzer = SQLiFuzzer(
                        baseUrl=args.start_url,
                        useCrawler= False,
                        wordlistPath=wordlistSqli,
                        outputToFile=args.output_to_file,
                        session=sess,
                        auth=False,
                        bailEvent=bail
                    )

                    res = fuzzer.SQLiFuzz([form])

                    if res:
                        if args.report_all:
                            results.extend(res)
                        else:
                            results.extend([v for v in res if v.get("type") != "potential_sqli"])

                if args.fuzz_sqli_b:

                    print(f"[Thread] SQLi Blind Form Fuzzing: {fullUrl}")
                    bail = threading.Event() if args.bail_on_hit else None
                    fuzzer = SQLiFuzzer(
                        baseUrl=args.start_url,
                        useCrawler=False,
                        wordlistPath=wordlistSqli,
                        outputToFile=args.output_to_file,
                        session=sess,
                        auth=False,
                        bailEvent=bail
                    )

                    res = fuzzer.SQLiBlindFuzz([form])

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
                    uniqueUrls = {}

                    for ep in endpoints:
                        parsedPath = urlparse(ep["url"]).path or "/"
                        baseDir = str(PurePosixPath(getDirectories(parsedPath))).rstrip("/")

                        if baseDir not in uniqueUrls:
                            uniqueUrls[baseDir] = ep
                    phaseEndpoints = list(uniqueUrls.values())
                else:
                    phaseEndpoints = endpoints

                # Update visited
                for ep in phaseEndpoints:
                    p = urlparse(ep["url"]).path or "/"
                    d = getDirectories(p)
                    globalVisitedPaths.add(d)

                if args.fuzz_paths or args.fuzz_params or args.xss_params:
                    print(f"\n[+] Starting threaded fuzzing on discovered endpoints... \n")
                    sessPool = buildSessions(args.auth, args.username, args.password, args.start_url, args.login_path)
                    try:
                        with ThreadPoolExecutor(max_workers=cfg["concurrency"]["max_workers"]) as executor:
                            # Run fuzzer using threads across all endpoints assigning a session from the session pool
                            futures = []
                            for i, ep in enumerate(phaseEndpoints):
                                sess = sessPool[i % len(sessPool)]
                                futures.append(executor.submit(fuzzEndpoint, ep, sess))

                            for future in as_completed(futures):
                                results = future.result()
                                if results:
                                    allVulnerabilities.extend(results)
                    # Close sessions and delete the pool
                    finally:
                        for sess in sessPool:
                            try:
                                sess.close()
                            except Exception:
                                pass
                        del sessPool

                if args.xss_forms or args.xss_stored or args.fuzz_sqli or args.fuzz_sqli_b:
                    print(f"\n[+] Starting threaded fuzzing on discovered Forms... \n")
                    sessPool = buildSessions(args.auth, args.username, args.password, args.start_url, args.login_path)
                    try:
                        with ThreadPoolExecutor(max_workers=cfg["concurrency"]["max_workers"]) as executor:
                            # Run fuzzer using threads across all forms assigning a session from the session pool
                            futures = []
                            for i, form in enumerate(forms):
                                sess = sessPool[i % len(sessPool)]
                                futures.append(executor.submit(fuzzForm, form, sess))

                            for future in as_completed(futures):
                                res = future.result()
                                if res:
                                    allVulnerabilities.extend(res)
                    # Close sessions and delete the pool
                    finally:
                        for sess in sessPool:
                            try:
                                sess.close()
                            except Exception:
                                pass
                        del sessPool

                if args.xss_dom:
                    print(f"\n[+] Running Dom XSS on discovered forms/endpoints...\n")
                    domSessPool = buildSessions(args.auth, args.username, args.password, args.start_url, args.login_path)
                    domSess = domSessPool[0] if domSessPool else None
                    bail = threading.Event() if args.bail_on_hit else None
                    fuzzer = XSSFuzzer(
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

                    res = fuzzer.domXSS(forms=rawDomForms, endpoints=endpoints)

                    if res:
                        for vul in res:
                            vul["type"] = "xss_dom"

                        allVulnerabilities.extend(res)

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
            fuzzerPrint(allVulnerabilities, output_to_file=args.output_to_file, filename="FuzzerOutput.txt")


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
                fuzzerPrint(results, output_to_file=args.output_to_file, filename="FuzzerOutput.txt")

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
                    for p in getParents(args.start_url):
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
                fuzzerPrint(results, output_to_file=args.output_to_file, filename="FuzzerOutput.txt")
