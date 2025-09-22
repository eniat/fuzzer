from pathlib import Path

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



def fuzzerPrint(vulnerabilities, output_to_file= False, filename="fuzzer-output.txt"):
    """
        Prints fuzzer results to console and file
    """
    if vulnerabilities:
        print("\n[+] Vulnerabilities discovered:")

        for vuln in vulnerabilities:
            if vuln["type"] == "interesting_200":
                print(f"  - [INTERESTING 200] {vuln['url']}")
            else:
                print(f"  - [{vuln['type'].upper()}] {vuln['url']}")
            print(f"    Payload:       {vuln['payload']}")
            print(f"    Status Code:   {vuln.get('status_code', 'N/A')}")
            print(f"    Indicator Hit: {vuln.get('indicator', 'N/A')}")

            cnt = vuln.get("count")
            if isinstance(cnt, int) and cnt > 1:
                print(f"    Count:         {cnt}")

            samples = (vuln.get("payload_samples") or [])

            samples = [s for s in samples if s != vuln.get('payload')]
            if samples:
                print(f"    Payload Samples: {samples[:5]}")
            print()

        if output_to_file:
            p = Path(filename)
            if p.parent and not p.parent.exists():
                p.parent.mkdir(parents=True, exist_ok=True)

            with open(p, "w", encoding="utf-8", errors="replace") as f:
                for vuln in vulnerabilities:
                    if vuln.get("type") == "interesting_200":
                        f.write(f"  - [INTERESTING 200] {vuln.get('url')}\n")
                    else:
                        f.write(f"  - [{str(vuln.get('type', '')).upper()}] {vuln.get('url')}\n")

                    f.write(f"  Payload:       {vuln.get('payload')}\n")
                    f.write(f"  Status Code:   {vuln.get('status_code', 'N/A')}\n")
                    f.write(f"  Indicator Hit: {vuln.get('indicator', 'N/A')}\n")

                    cnt = vuln.get("count")
                    if isinstance(cnt, int) and cnt > 1:
                        f.write(f"  Count:         {cnt}\n")

                    samples = vuln.get("payload_samples") or []
                    extra_samples = [s for s in samples if s != vuln.get("payload")]
                    if extra_samples:
                        f.write(f"  Payload Samples: {extra_samples}\n")

                    # Keep snippet only in file output
                    snippet = (vuln.get('response_snippet', '') or '').replace(chr(10), ' ')[:200]
                    if snippet:
                        f.write(f"  Snippet:       {snippet}\n")

                    f.write("-" * 50 + "\n")
    else:
        print("[-] No vulnerabilities found.")