from typing import Optional

from ..core.reporting import crawlerPrint, fuzzerPrint, crawlerJson, fuzzerJson, Finding
from ..runtime.ports import RepoService


class DefaultRepo(RepoService):
    """
        Wrapper for Reporting functions
    """
    def crawler_print(self, endpoints: Optional[list[dict]], forms: Optional[list[dict]],
                      output_to_file: bool = False, file_name: str = "crawler-output.txt") -> None:
        return crawlerPrint(endpoints, forms, output_to_file, file_name)

    def fuzzer_print(self, vulnerabilities: Optional[list[Finding]], output_to_file: bool = False,
                     file_name: str = "fuzzer-output.txt") -> None:
        return fuzzerPrint(vulnerabilities, output_to_file, file_name)

    def crawler_json(self, endpoints: Optional[list[dict]], forms: Optional[list[dict]], output_to_json: bool = False,
                     file_name: str ="crawler-output.json") -> None:
        return crawlerJson(endpoints, forms, output_to_json, file_name)

    def fuzzer_json(self, vulnerabilities: Optional[list[Finding]], output_to_json: bool = False,
                    file_name: str ="fuzzer-output.json" ) -> None:
        return fuzzerJson(vulnerabilities, output_to_json, file_name)