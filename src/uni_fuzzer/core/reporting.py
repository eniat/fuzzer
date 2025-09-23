import json
from pathlib import Path
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

# Creating a dataclass for all vulnerabilities output
@dataclass
class Finding:
    type: str
    url: str
    method: str
    param: Optional[str] = None
    payload: Optional[str] = None
    indicator: str = ""
    status_code: Optional[int] = None
    count: Optional[int] = None
    payload_samples: List[str] = field(default_factory=list)
    response_snippet: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        dic = asdict(self)
        if dic.get("response_snippet"):
            dic["response_snippet"] = str(dic["response_snippet"])[:200]
        return dic

def crawlerPrint(endpoints, forms, output_to_file=False, filename="crawler-output.txt"):
    """
        Prints crawler results to console and file
    """
    print("\n[+] Starting Crawler...")

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

    # File output
    if output_to_file:
        p = Path(filename)
        if p.parent and not p.parent.exists():
            p.parent.mkdir(parents=True, exist_ok=True)

        with open(p, "w", encoding="utf-8", errors="replace") as f:
            f.write(f"{len(endpoints)} endpoints discovered.\n")
            f.write(f"{len(forms)} forms discovered.\n\n")

            f.write("Endpoints:\n")
            for ep in endpoints:
                f.write(f"  {ep['method']} {ep['url']} (params: {ep['params']})\n")

            f.write("\nForms:\n")
            for fm in forms:
                f.write(f"  {fm['method']} {fm['url']} (fields: {fm['formFields']})\n")



def fuzzerPrint(vulnerabilities: List[Finding], output_to_file= False, filename="fuzzer-output.txt"):
    """
        Prints fuzzer results to console and file
    """
    if vulnerabilities:
        print("\n[+] Vulnerabilities discovered:")

        for vuln in vulnerabilities:
            if vuln.type == "interesting_200":
                print(f"  - [INTERESTING 200] {vuln.url}")
            else:
                print(f"  - [{vuln.type.upper()}] {vuln.url}")
            print(f"    Payload:       {vuln.payload}")
            print(f"    Status Code:   {vuln.status_code if vuln.status_code is not None else 'N/A'}")
            print(f"    Indicator Hit: {vuln.indicator or 'N/A'}")

            if isinstance(vuln.count, int) and vuln.count > 1:
                print(f"    Count:         {vuln.count}")

            samples = [s for s in (vuln.payload_samples or []) if s != vuln.payload]
            if samples:
                print(f"    Payload Samples: {samples[:5]}")
            print()

        if output_to_file:
            p = Path(filename)
            if p.parent and not p.parent.exists():
                p.parent.mkdir(parents=True, exist_ok=True)

            with open(p, "w", encoding="utf-8", errors="replace") as f:
                for vuln in vulnerabilities:
                    if vuln.type == "interesting_200":
                        f.write(f"  - [INTERESTING 200] {vuln.url}\n")
                    else:
                        f.write(f"  - [{vuln.type.upper()}] {vuln.url}\n")

                    f.write(f"  Payload:       {vuln.payload}\n")
                    f.write(f"  Status Code:   {vuln.status_code if vuln.status_code is not None else 'N/A'}\n")
                    f.write(f"  Indicator Hit: {vuln.indicator or 'N/A'}\n")

                    if isinstance(vuln.count, int) and vuln.count > 1:
                        f.write(f"  Count:         {vuln.count}\n")

                    samples = [s for s in (vuln.payload_samples or []) if s != vuln.payload]
                    if samples:
                        f.write(f"  Payload Samples: {samples}\n")

                    snippet = (vuln.response_snippet or "").replace(chr(10), " ")[:200]
                    if snippet:
                        f.write(f"  Snippet:       {snippet}\n")

                    f.write("-" * 50 + "\n")
    else:
        print("[-] No vulnerabilities found.")

def crawlerJson(endpoints, forms, output_to_json=False, filename="crawler-output.json"):
    """
        Prints crawler results to json file
    """
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "endpoints_count": len(endpoints or []),
            "forms_count": len(forms or [])
        },
        "endpoints": [
            {
                "method": ep.get("method"),
                "url": ep.get("url"),
                "params": ep.get("params"),
            } for ep in (endpoints or [])
        ],
        "forms": [
            {
                "method": fm.get("method"),
                "url": fm.get("url"),
                "fields": fm.get("formFields"),
            } for fm in (forms or [])
        ],
    }

    if output_to_json:
        path = Path(filename)
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)



def fuzzerJson(vulnerabilities: List[Finding], output_to_json= False, filename="fuzzer-output.json"):
    """
        Prints fuzzer results to json file
    """
    findings = [vuln.to_dict() for vuln in (vulnerabilities or [])]
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {"findings_count": len(findings)},
        "findings": findings
    }

    if output_to_json:
        path = Path(filename)
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)