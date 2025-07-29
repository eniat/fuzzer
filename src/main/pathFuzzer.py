from urllib.parse import urljoin, urlparse, parse_qs, urldefrag

from crawler import Crawler

class PathFuzzer:

    def __init__(self, baseUrl, useCrawler, wordlistPath= None, outputToFile = False):
        self.baseUrl = baseUrl
        self.useCrawler = useCrawler
        self.wordlistPath = wordlistPath
        self.outputToFile = outputToFile
        self.payloads = self.loadWordlist()

    def loadWordlist(self):
        """
            Load payload from wordlist
        """
        try:
            with open(self.wordlistPath, 'r') as f:
                # Strips the lines
                return [line.strip() for line in f if line.strip()]
        except Exception as e :
            # On error raise exception
            raise RuntimeError( f"Failed to load wordlist from {self.wordlistPath}: {e}")

    def getInitalPaths(self):
        """
            Get paths from the crawler or use base
        """
        # Runs crawler to get paths
        if self.useCrawler:
            crawler = Crawler(outputToFile= False)
            endpoints, _ = crawler.crawl(self.baseUrl)
            return list(set(ep ["url"] for ep in endpoints )), endpoints
        # If crawler isn't wanted uses baseUrl as starting point
        else:
            parsed = urlparse(self.baseUrl)
            return [parsed.path or "/"], [{"url" : parsed.path or "/", "params": list(parse_qs(parsed.query).keys())} ]


    def  fuzzPath(self):
        """
            Fuzz the URL path using the payload
        """
        pass

    def fuzzParams(self):
        """
            Fuzz query params
        """
        pass

if __name__ == "__main__":

    baseUrl = "http://localhost:3000/#/"
    useCrawler = True
    wordlistPath = "../resources/wordlists/small.txt"

    # Create an instance of PathFuzzer
    fuzzer = PathFuzzer(baseUrl, useCrawler, wordlistPath=wordlistPath)

    # Test loadWordlist
    print(f"Loaded Payloads:{fuzzer.payloads}")

    # Test getInitialPaths
    paths, _ = fuzzer.getInitalPaths()
    print(f"\nInitial Paths:{paths}")


