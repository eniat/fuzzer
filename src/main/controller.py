import argparse
from crawler import Crawler
from pathFuzzer import PathFuzzer

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
            outputToFile=args.output_to_file
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

        if args.fuzz_paths and args.fuzz_params:
            print( "\n[+] Starting Path and Parameter fuzzing...")
        elif args.fuzz_paths:
            print("\n[+] Starting Path Traversal Fuzzing...")
        elif args.fuzz_params:
            print("\n[+] Starting Parameter Traversal Fuzzing...")

        fuzzer = PathFuzzer(
            baseUrl=args.start_url,
            useCrawler= args.use_crawler,
            wordlistPath= args.wordlist,
            outputToFile=args.output_to_file,
            isDVWA= args.dvwa
        )
        fuzzer.run(fuzzParams=args.fuzz_params, fuzzPaths=args.fuzz_paths)

if __name__ == "__main__":
    main()
