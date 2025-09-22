import argparse
from uni_fuzzer.core.controller import run

def buildParser():

    parser = argparse.ArgumentParser(description="Run with specified settings")

    parser.add_argument("start_url", help="The starting URL")
    parser.add_argument("-c","--use-crawler", action="store_true", help="Use crawler to discover paths before fuzzing")
    parser.add_argument("-m","--crawler-mode", choices=["static", "dynamic", "both"], default="both",help="Crawling mode. Default = both")
    parser.add_argument("-n","--max-pages", type=int, default=50, help="Max pages to crawl")
    parser.add_argument("-r","--rate-limit", type=float, default=0.0,help="Delay between requests. Default = 0.0")
    parser.add_argument("-H","--no-headless", action="store_true", help="Run browser in headless")
    parser.add_argument("-f","--fuzz-paths", action="store_true", help="Enable path traversal fuzzing")
    parser.add_argument("-p","--fuzz-params", action="store_true", help="Enable parameter fuzzing. (requires FUZZ in url)")
    parser.add_argument("-x","--xss-params", action="store_true", help="Enable XSS parameter fuzzing. (requires FUZZ in url)")
    parser.add_argument("-F","--xss-forms", action="store_true", help="Enable XSS form fuzzing. (requires crawler to be used)")
    parser.add_argument("-S","--xss-stored", action="store_true",help="Enable stored XSS fuzzing. (requires crawler to be used)")
    parser.add_argument("-d","--xss-dom", action="store_true",help="Enable dom XSS fuzzing. (requires crawler and doesn't use wordlist")
    parser.add_argument("-s","--fuzz-sqli", action="store_true",help="Enable SQL injection fuzzing. (requires crawler to be used)")
    parser.add_argument("-b","--fuzz-sqli-b", action="store_true", help="Enable SQL Blind injection fuzzing. (requires crawler to be used)")
    parser.add_argument("-w","--wordlist", type=str, help="Path to payload wordlist for fuzzing")
    parser.add_argument("-wp","--pwordlist", type=str, help="Wordlist for path traversal and parameter fuzzing")
    parser.add_argument("-wx","--xwordlist", type=str, help="Wordlist for XSS fuzzing")
    parser.add_argument("-ws","--swordlist", type=str, help="Wordlist for SQLi fuzzing")
    parser.add_argument("-A","--all", action="store_true", help="Run all fuzzers ")
    parser.add_argument("-o","--output-to-file", action="store_true", help="Save output to a file")
    parser.add_argument("-l","--llm", type =str, help="Natural language prompt to filter the default wordlist using local ML")
    parser.add_argument("-a","--auth", action="store_true", help="Use if webapp is behind a login page")
    parser.add_argument("-u","--username", type=str, help="Username for Selenium/HTTP login")
    parser.add_argument("-pw","--password", type=str, help="Password for Selenium/HTTP login")
    parser.add_argument("-k","--login-path", type=str, help="Login path or absolute URL")
    parser.add_argument("-R","--report-all", action="store_true", default=False, help="Include potential and path 'interesting' findings in the report.")
    parser.add_argument("-B", "--bail-on-hit", action="store_true", help="Stop fuzzing as soon as the first hit is detected.")
    parser.add_argument("-L", "--log", action="store_true", help="Enable logging")
    parser.add_argument("-ll", "--log-level", default="INFO", choices=["DEBUG", "INFO", "DEBUG"], help="Logging level")
    parser.add_argument("-lf", "--log-file", default="uni-fuzzer.log", help="set the log file name. default uni-fuzzer.log")
    parser.add_argument("-J", "--log-json", action="store_true", help="Log as JSON format")
    parser.add_argument("-C", "--log-console", action="store_true", help="Also log to console")

    return parser

def main():
    parser = buildParser()
    args = parser.parse_args()
    run(args)

if __name__ == "__main__":
    main()