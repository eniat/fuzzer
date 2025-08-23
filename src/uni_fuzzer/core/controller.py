import argparse
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import PurePosixPath, Path

from uni_fuzzer.crawler.crawler import Crawler
from uni_fuzzer.fuzzers.path import PathFuzzer
from uni_fuzzer.llm.semantic_llm import filterML
from uni_fuzzer.fuzzers.xss import XSSFuzzer
from uni_fuzzer.fuzzers.sqli import SQLiFuzzer
from uni_fuzzer.core.reporting import crawlerPrint, fuzzerPrint
from uni_fuzzer.core.utility import get_cfg, isFuzzableField
cfg = get_cfg()

WORDLIST_DIR = Path(__file__).resolve().parent.parent / "resources" / "wordlists"

def sortWordlist(name):
    """
        Allows wordlist to be passed by name as well as full file location
    """
    # if it's a path that's valid return path
    p = Path(name)
    if p.exists():
        return p

    # Check resources/wordlists by short name
    candidate = WORDLIST_DIR / f"{name}.txt"
    if candidate.exists():
        return candidate

    raise FileNotFoundError(f"Wordlist '{name}' not found in {WORDLIST_DIR}")

def getdirectories(path):
    """
        Helper for stripping filenames and only leaving directories
    """

    exts = tuple(cfg.get("paths", {}).get("file_extensions", [
        ".php", ".html", ".asp", ".aspx", ".jsp", ".py", ".rb", ".zip"
    ]))

    segments = path.rstrip("/").split("/")

    if segments and any(segments[-1].lower().endswith(ext) for ext in exts):
        segments = segments[:-1]

    baseDir = "/" + "/".join(segments) if segments else "/"
    return str(PurePosixPath(baseDir))

def getParents(path):
    """
        Gets the parents of the given URL
    """
    p = PurePosixPath(urlparse(path).path or "/")

    chain = []
    for parent in p.parents:
        if str(parent) != ".":
            chain.append(str(parent) if str(parent).startswith("/") else f"/{parent}")

    chain.append(str(p) if str(p).startswith("/") else f"/{p}")

    # normalize and dedupe
    seen, out = set(), []

    for x in chain:
        n = str(PurePosixPath(x)).rstrip("/") or "/"
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out

def main():

    parser = argparse.ArgumentParser(description="Run with specified settings")

    parser.add_argument("start_url", help="The starting URL")
    parser.add_argument("--use-crawler", action="store_true", help="Use crawler to discover paths before fuzzing")
    parser.add_argument("--crawler-mode", choices=["static", "dynamic", "both"], default="both",help="Crawling mode. Default = both")
    parser.add_argument("--max-pages", type=int, default=20, help="Max pages to crawl")
    parser.add_argument("--rate-limit", type=float, default=0.0,help="Delay between requests. Default = 0.0")
    parser.add_argument("--no-headless", action="store_true", help="Run browser in headless")
    parser.add_argument("--fuzz-paths", action="store_true", help="Enable path traversal fuzzing")
    parser.add_argument("--fuzz-params", action="store_true", help="Enable parameter fuzzing. (requires FUZZ in url)")
    parser.add_argument("--xss-params", action="store_true", help="Enable XSS parameter fuzzing. (requires FUZZ in url)")
    parser.add_argument("--xss-forms", action="store_true", help="Enable XSS form fuzzing. (requires crawler to be used)")
    parser.add_argument("--xss-stored", action="store_true",help="Enable stored XSS fuzzing. (requires crawler to be used)")
    parser.add_argument("--xss-dom", action="store_true",help="Enable dom XSS fuzzing. (requires crawler and doesn't use wordlist")
    parser.add_argument("--fuzz-sqli", action="store_true",help="Enable SQL injection fuzzing. (requires crawler to be used)")
    parser.add_argument("--wordlist", type=str, help="Path to payload wordlist for fuzzing")
    parser.add_argument("--output-to-file", action="store_true", help="Save output to a file")
    parser.add_argument("--llm", type =str, help="Natural language prompt to filter the wordlist using local ML")
    parser.add_argument("--auth", action="store_true", help="Use if webapp is behind a login page")
    parser.add_argument("--username", type=str, help="Username for Selenium login")
    parser.add_argument("--password", type=str, help="Password for Selenium login")
    parser.add_argument("--login-path", type=str, help="Login path or absolute URL")

    args = parser.parse_args()

    if args.wordlist:
        args.wordlist = sortWordlist(args.wordlist)

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
            and not args.fuzz_sqli):

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
        sharedSession = getattr(crawler, "session", None)

        crawlerPrint(endpoints, forms, output_to_file=args.output_to_file, filename="CrawlerOutput.txt")

    else:

        if (not args.wordlist) and (args.fuzz_paths or args.fuzz_params or args.xss_params or args.xss_forms or args.xss_stored or args.fuzz_sqli):
            print("The Fuzzer requires a --wordlist to run for the selected mode")
            return

        if args.use_crawler:

            # Global storage to remove duplicate fuzzing
            globalVisitedPaths = set()
            globalVisitedFuzzPaths = set()

            allVulnerabilities = []

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
            sharedSession = getattr(crawler, "session", None)

            crawlerPrint(endpoints, forms, output_to_file=args.output_to_file, filename="CrawlerOutput.txt")

            rawDomForms = forms[:]

            forms = [
                f for f in forms
                if any(isFuzzableField(field) for field in f.get("formFields", []))
            ]

            if not endpoints and not forms:

                print("[-] No endpoints or forms found by crawler.")
                if not (args.xss_forms or args.xss_stored or args.xss_dom or args.fuzz_sqli):
                    return

            # Derive base url for relative links
            parsed = urlparse(args.start_url)
            base = f"{parsed.scheme}://{parsed.netloc}"

            if args.fuzz_paths:
                # Filter to unique base directories
                uniqueUrls = {}
                for ep in endpoints:
                    parsedPath = urlparse(ep["url"]).path or "/"
                    baseDir = str(PurePosixPath(getdirectories(parsedPath))).rstrip("/")

                    if baseDir not in uniqueUrls:
                        uniqueUrls[baseDir] = ep
                UniqueEndpoints = list(uniqueUrls.values())

            else:
                UniqueEndpoints = endpoints

            #  Add to visited directories
            for ep in UniqueEndpoints:
                p = urlparse(ep["url"]).path or "/"
                d = getdirectories(p)
                globalVisitedPaths.add(d)

            print(f"[+] Beginning fuzzing... \n")

            def fuzzEndpoint(ep):
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

                    fuzzer = PathFuzzer(
                        baseUrl= fullUrl,
                        wordlistPath =args.wordlist,
                        outputToFile= args.output_to_file,
                        isSilent = True,
                        session=sharedSession,
                        auth=args.auth,
                    )
                    fuzzer.visitedPaths = globalVisitedPaths
                    fuzzer.visitedFuzzPaths = globalVisitedFuzzPaths

                    for path in getParents(fullUrl):
                        fuzzer.fuzzPath(path)

                    if fuzzer.vulnerablePaths:
                        results.extend(fuzzer.vulnerablePaths)

                if args.fuzz_params and params:

                    # Param fuzzing
                    fuzzQuery = "&".join([f"{p}=FUZZ" for p in params])
                    fuzzedUrl = f"{fullUrl}?{fuzzQuery}" if "?" not in fullUrl else f"{fullUrl}&{fuzzQuery}"

                    print(f"[Thread] Param Fuzzing: {fuzzedUrl}")

                    fuzzer = PathFuzzer(
                        baseUrl= fuzzedUrl,
                        wordlistPath= args.wordlist,
                        outputToFile= args.output_to_file,
                        isSilent= True,
                        session=sharedSession,
                        auth=args.auth,
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

                    fuzzer = XSSFuzzer(
                        baseUrl= fuzzedUrl,
                        useCrawler=False,
                        wordlistPath=args.wordlist,
                        outputToFile=args.output_to_file,
                        isSilent =True,
                        headless=not args.no_headless,
                        session=sharedSession,
                        auth=args.auth,
                        loginUsername=args.username,
                        loginPassword=args.password,
                        loginPath=args.login_path
                    )

                    res = fuzzer.paramXSS()

                    if res:
                        for vuln in res:
                            vuln["type"] = "xss"

                        results.extend(res)

                return results

            def fuzzForm(form):

                results = []

                fullUrl = form.get("url")
                if fullUrl and not fullUrl.startswith("http"):
                    fullUrl = urljoin(base, fullUrl)

                if args.xss_forms:

                    print(f"[Thread] XSS Form Fuzzing: {fullUrl}")
                    fuzzer = XSSFuzzer(
                        baseUrl=args.start_url,
                        useCrawler=False,
                        wordlistPath=args.wordlist,
                        outputToFile=args.output_to_file,
                        isSilent=True,
                        headless=not args.no_headless,
                        session=sharedSession,
                        auth=args.auth,
                        loginUsername=args.username,
                        loginPassword=args.password,
                        loginPath=args.login_path
                    )

                    res = fuzzer.formXSS([form])

                    if res:
                        for vuln in res:
                            vuln["type"] = "xss_form"

                        results.extend(res)

                if args.xss_stored:

                    print(f"[Thread] XSS Stored Fuzzing: {fullUrl}")
                    fuzzer = XSSFuzzer(
                        baseUrl=args.start_url,
                        useCrawler= False,
                        wordlistPath=args.wordlist,
                        outputToFile=args.output_to_file,
                        isSilent=True,
                        headless=not args.no_headless,
                        session=sharedSession,
                        auth=args.auth,
                        loginUsername=args.username,
                        loginPassword=args.password,
                        loginPath=args.login_path
                    )

                    # Pass directories of forms/ shared directory endpoints
                    formDir = getdirectories(urlparse(fullUrl).path)
                    relevantEndpoints = [
                        ep["url"] if ep["url"].startswith("http") else urljoin(base, ep["url"])
                        for ep in endpoints
                        if getdirectories(urlparse(ep["url"]).path) == formDir
                    ]

                    res = fuzzer.storedXSS([form], endpoints=relevantEndpoints)

                    if res:
                        for vuln in res:
                            vuln["type"] = "xss_stored"

                        results.extend(res)

                if args.fuzz_sqli:

                    print(f"[Thread] SQLi Form Fuzzing: {fullUrl}")
                    fuzzer = SQLiFuzzer(
                        baseUrl=args.start_url,
                        useCrawler= False,
                        wordlistPath=args.wordlist,
                        outputToFile=args.output_to_file,
                        isSilent=True,
                        session=sharedSession,
                        auth=args.auth,
                        loginUsername=args.username,
                        loginPassword=args.password,
                        loginPath=args.login_path
                    )

                    res = fuzzer.SQLiFuzz([form])

                    if res:
                        for vuln in res:
                            if vuln.get("type") == "vulnerable":
                                vuln["type"] = "sqli"
                            elif vuln.get("type") == "potential":
                                vuln["type"] = "sqli_potential"

                        results.extend(res)

                return results

            if args.fuzz_paths or args.fuzz_params or args.xss_params or args.fuzz_sqli:
                print(f"\n[+] Starting threaded fuzzing on discovered endpoints... \n")
                with ThreadPoolExecutor(max_workers=cfg["concurrency"]["max_workers"]) as executor:
                    # Run fuzzer using threads across all endpoints
                    futures = [executor.submit(fuzzEndpoint, ep) for ep in UniqueEndpoints]

                    for future in as_completed(futures):
                        results = future.result()
                        allVulnerabilities.extend(results)

            if args.xss_forms or args.xss_stored or args.fuzz_sqli:
                print(f"\n[+] Starting threaded fuzzing on discovered Forms... \n")
                with ThreadPoolExecutor(max_workers=cfg["concurrency"]["max_workers"]) as executor:
                    # Run fuzzer using threads across all forms
                    futures = [executor.submit(fuzzForm, form) for form in forms]

                    for future in as_completed(futures):
                        res = future.result()
                        if res:
                            allVulnerabilities.extend(res)

            if args.xss_dom:
                print(f"\n[+] Running Dom XSS on discovered forms/endpoints...\n")

                fuzzer = XSSFuzzer(
                    baseUrl=args.start_url,
                    useCrawler=False,
                    wordlistPath=args.wordlist,
                    outputToFile=args.output_to_file,
                    isSilent=True,
                    headless=not args.no_headless,
                    session=sharedSession,
                    auth=args.auth,
                    loginUsername=args.username,
                    loginPassword=args.password,
                    loginPath=args.login_path
                )

                res = fuzzer.domXSS(forms=rawDomForms, endpoints=endpoints)

                if res:
                    for vul in res:
                        vul["type"] = "xss_dom"

                    allVulnerabilities.extend(res)

            fuzzerPrint(allVulnerabilities, output_to_file=args.output_to_file, filename="FuzzerOutput.txt")


        else:
            # Fuzz a single target
            if args.xss_params:

                fuzzer = XSSFuzzer(
                    baseUrl=args.start_url,
                    useCrawler=False,
                    wordlistPath=args.wordlist,
                    outputToFile=args.output_to_file,
                    isSilent=True,
                    headless=not args.no_headless,
                    session=None,
                    auth=args.auth,
                    loginUsername=args.username,
                    loginPassword=args.password,
                    loginPath=args.login_path
                )

                results = fuzzer.paramXSS()

                fuzzerPrint(results, output_to_file=args.output_to_file, filename="FuzzerOutput.txt")

            else:

                fuzzer = PathFuzzer(
                    baseUrl=args.start_url,
                    wordlistPath=args.wordlist,
                    outputToFile=args.output_to_file,
                    isSilent=True,
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

                results.extend(fuzzer.vulnerablePaths)

                fuzzerPrint(results, output_to_file=args.output_to_file, filename="FuzzerOutput.txt")


if __name__ == "__main__":
    main()
