import argparse
from crawler import Crawler
from pathFuzzer import PathFuzzer
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

def main():

    parser = argparse.ArgumentParser(description="Run with specified settings")

    parser.add_argument("start_url", help="The starting URL")
    parser.add_argument("--use-crawler", action="store_true", help="Use crawler to discover paths before fuzzing")
    parser.add_argument("--mode", choices=["static", "dynamic", "both"], default="both",help="Crawling mode. Default = both")
    parser.add_argument("--max-pages", type=int, default=10, help="Max pages to crawl")
    parser.add_argument("--rate-limit", type=float, default=0.0,help="Delay between requests. Default = 0.0")
    parser.add_argument("--no-headless", action="store_true", help="Run browser in headless")
    parser.add_argument("--fuzz-paths", action="store_true", help="Enable path traversal fuzzing")
    parser.add_argument("--fuzz-params", action="store_true", help="Enable parameter fuzzing")
    parser.add_argument("--wordlist", type=str, help="Path to payload wordlist for fuzzing")
    parser.add_argument("--output-to-file", action="store_true", help="Save output to a file")
    # Testing specific
    parser.add_argument("--dvwa", action="store_true", help="Enable auto-login for DVWA")
    args = parser.parse_args()

    # If no fuzzer selected run crawler on its own
    if not args.fuzz_paths and not args.fuzz_params:

        crawler = Crawler(
            mode=args.mode,
            maxPages=args.max_pages,
            rateLimit=args.rate_limit,
            headless= not args.no_headless,
            outputToFile=args.output_to_file,
            isDVWA = args.dvwa
        )

        print("\n[+] Starting Crawler...")

        endpoints, forms = crawler.crawl(args.start_url)

        # Check that at least one endpoint is discovered
        if endpoints:
            print(f"{len(endpoints)} endpoints discovered.")
        else:
            print("No endpoints discovered.")

        # Check that at least one form is discovered
        if forms:
            print(f"{len(forms)} forms discovered.")
        else:
            print("No forms discovered.")

        # Print
        print("\nEndpoints:")
        for ep in endpoints:
            print(f"  {ep['method']} {ep['url']} (params: {ep['params']})")

        print("\nForms:")
        for fm in forms:
            print(f"  {fm['method']} {fm['url']} (fields: {fm['formFields']})")

    else:

        if not args.wordlist:
            print("The Fuzzer requires a --wordlist to run")
            return

        if args.use_crawler:

            allVulnerabilities = []

            print("\n[+] Using crawler to discover endpoints...")

            crawler = Crawler(
                mode= args.mode,
                maxPages= args.max_pages,
                rateLimit= args.rate_limit,
                headless=not args.no_headless,
                outputToFile= args.output_to_file,
                isDVWA= args.dvwa
            )
            endpoints, _ = crawler.crawl(args.start_url)

            if not endpoints:

                print("[-] No endpoints found by crawler.")
                return

            parsed = urlparse(args.start_url)
            base = f"{parsed.scheme}://{parsed.netloc}"

            print(f"[+] {len(endpoints)} endpoints discovered. Beginning fuzzing... \n")

            def fuzz(ep):
                """
                    To allow for parallel calls
                """

                results = []

                rawUrl = ep["url"]
                params = ep.get("params", [])
                fullUrl = rawUrl if rawUrl.startswith("http") else urljoin(base, rawUrl)

                if args.fuzz_paths:

                    print(f"[Thread] Path Fuzzing: {fullUrl}")

                    fuzzer = PathFuzzer(
                        baseUrl= fullUrl,
                        useCrawler= False,
                        wordlistPath =args.wordlist,
                        outputToFile= args.output_to_file,
                        isDVWA= args.dvwa,
                        isSilent = True
                    )

                    res = fuzzer.run(fuzzParams=False, fuzzPaths=True)
                    if res:
                        results.extend(res)

                if args.fuzz_params and params:

                    fuzzQuery = "&".join([f"{p}=FUZZ" for p in params])
                    fuzzedUrl = f"{fullUrl}?{fuzzQuery}" if "?" not in fullUrl else f"{fullUrl}&{fuzzQuery}"

                    print(f"[Thread] Param Fuzzing: {fuzzedUrl}")

                    fuzzer = PathFuzzer(
                        baseUrl= fuzzedUrl,
                        useCrawler= False,
                        wordlistPath= args.wordlist,
                        outputToFile= args.output_to_file,
                        isDVWA= args.dvwa,
                        isSilent= True
                    )

                    res = fuzzer.run(fuzzParams=True, fuzzPaths=False)
                    if res:
                        results.extend(res)
                return results

            print(f"\n[+] {len(endpoints)} endpoints discovered. Starting threaded fuzzing... \n")

            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(fuzz, ep) for ep in endpoints]

                for future in as_completed(futures):
                    results = future.result()
                    allVulnerabilities.extend(results)

            if allVulnerabilities:
                print("\n[+] Vulnerabilities discovered:")

                for vuln in allVulnerabilities:
                    print(f"  - Type: {vuln['type']}, URL: {vuln['url']}, Payload: {vuln['payload']}")

                if args.output_to_file:
                    with open("pathFuzzerOutput.txt", "w") as f:
                        for vuln in allVulnerabilities:

                            f.write(f"{vuln['type'].upper()} | {vuln['url']} | Payload: {vuln['payload']}\n")


            else:
                print("[-] No vulnerabilities found.")

        else:
            # Fuzz a single target
            fuzzer = PathFuzzer(
                baseUrl=args.start_url,
                useCrawler=False,
                wordlistPath=args.wordlist,
                outputToFile=args.output_to_file,
                isDVWA=args.dvwa,
                isSilent = True
            )

            results = fuzzer.run(fuzzParams=args.fuzz_params, fuzzPaths=args.fuzz_paths)

            if results:
                print("\n[+] Vulnerabilities discovered:")

                for vuln in results:
                    print(f"  - Type: {vuln['type']}, URL: {vuln['url']}, Payload: {vuln['payload']}")

                if args.output_to_file:
                    with open("pathFuzzerOutput.txt", "w") as f:
                        for vuln in results:
                            f.write(f"{vuln['type'].upper()} | {vuln['url']} | Payload: {vuln['payload']}\n")

            else:
                print("[-] No vulnerabilities found.")


if __name__ == "__main__":
    main()
