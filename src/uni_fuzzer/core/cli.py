import argparse
from uni_fuzzer.core.controller import run

def buildParser():

    parser = argparse.ArgumentParser(description="Run with specified settings")

    parser.add_argument("start_url", help="The starting URL")
    parser.add_argument("--use-crawler", action="store_true", help="Use crawler to discover paths before fuzzing")
    parser.add_argument("--crawler-mode", choices=["static", "dynamic", "both"], default="both",help="Crawling mode. Default = both")
    parser.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl")
    parser.add_argument("--rate-limit", type=float, default=0.0,help="Delay between requests. Default = 0.0")
    parser.add_argument("--no-headless", action="store_true", help="Run browser in headless")
    parser.add_argument("--fuzz-paths", action="store_true", help="Enable path traversal fuzzing")
    parser.add_argument("--fuzz-params", action="store_true", help="Enable parameter fuzzing. (requires FUZZ in url)")
    parser.add_argument("--xss-params", action="store_true", help="Enable XSS parameter fuzzing. (requires FUZZ in url)")
    parser.add_argument("--xss-forms", action="store_true", help="Enable XSS form fuzzing. (requires crawler to be used)")
    parser.add_argument("--xss-stored", action="store_true",help="Enable stored XSS fuzzing. (requires crawler to be used)")
    parser.add_argument("--xss-dom", action="store_true",help="Enable dom XSS fuzzing. (requires crawler and doesn't use wordlist")
    parser.add_argument("--fuzz-sqli", action="store_true",help="Enable SQL injection fuzzing. (requires crawler to be used)")
    parser.add_argument("--fuzz-sqli-b", action="store_true", help="Enable SQL Blind injection fuzzing. (requires crawler to be used)")
    parser.add_argument("--wordlist", type=str, help="Path to payload wordlist for fuzzing")
    parser.add_argument("--output-to-file", action="store_true", help="Save output to a file")
    parser.add_argument("--llm", type =str, help="Natural language prompt to filter the wordlist using local ML")
    parser.add_argument("--auth", action="store_true", help="Use if webapp is behind a login page")
    parser.add_argument("--username", type=str, help="Username for Selenium login")
    parser.add_argument("--password", type=str, help="Password for Selenium login")
    parser.add_argument("--login-path", type=str, help="Login path or absolute URL")
    parser.add_argument("--report-all", action="store_true", default=False, help="Include potential and path 'interesting' findings in the report.")

    return parser

def main():
    parser = buildParser()
    args = parser.parse_args()
    run(args)

if __name__ == "__main__":
    main()