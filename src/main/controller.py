import argparse
from crawler import Crawler

def main():

    parser = argparse.ArgumentParser(description="Run with specified settings")

    parser.add_argument("start_url", help="The starting URL")
    parser.add_argument("--mode", choices=["static", "dynamic", "both"], default="both",help="Crawling mode. Default = both")
    parser.add_argument("--max-pages", type=int, default=10, help="Max pages to crawl")
    parser.add_argument("--rate-limit", type=float, default=0.0,help="Delay between requests. Default = 0.0")
    parser.add_argument("--no-headless", action="store_true", help="Run browser in headless")
    parser.add_argument("--output-to-file", action="store_true", help="Save output to a file")

    args = parser.parse_args()

    crawler = Crawler(
        mode=args.mode,
        maxPages=args.max_pages,
        rateLimit=args.rate_limit,
        headless= not args.no_headless,
        outputToFile=args.output_to_file
    )

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

if __name__ == "__main__":
    main()
