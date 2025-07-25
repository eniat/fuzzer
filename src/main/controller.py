from crawler import Crawler

def testCrawler():

    startUrl = "http://localhost:3000"

    crawler = Crawler(
        mode='both',
        maxPages=10,
        rateLimit=0.0,
        headless=True,
        outputToFile=False
    )

    endpoints, forms = crawler.crawl(startUrl)

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
    testCrawler()
