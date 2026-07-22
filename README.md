# Integrated Crawler-Fuzzer for Web Vulnerability Testing
 ![tests](https://github.com/eniat/fuzzer/actions/workflows/tests.yml/badge.svg)

Web fuzzing toolkit with **crawlers** (both dynamic and static) and focused fuzzers for **Path Traversal**, **XSS** (params, forms, stored and DOM), and **SQL Injection** (error/content-based and blind timing/boolean).

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [CLI Usage](#cli-usage)
- [What Gets Reported](#what-gets-reported)
- [Benchmark Results](#benchmark-results)
- [Performance Tips](#performance-tips)
- [Security and Usage Notes](#security-and-usage-notes)
- [License](#license)

---
## Features

- **Crawler-first workflow** (optional): discover endpoints and forms automatically.
- **Path** suite:
  - fuzzer with recursion into live 200s and file/extension guards.
  - param based fuzzer.
- **XSS** suite:
  - Param & form reflected XSS (tokenized payloads, reflexivity probes)
  - Stored XSS (submit-then-revisit with settle window)
  - DOM XSS (Selenium headless, cookie handoff, DOM probes)
- **SQLi** suite:
  - Error/content-based detection
  - Blind (boolean diff + timing with median & serial confirmation)
- **Highly configurable**: concurrency pools, timeouts, headers, redirection policy, sample caps.
- **LLM-aided wordlist filtering** (optional prompt-based filter).
- **Clean output**: terminal + optional JSON. Smart **duplicate collapsing** across findings.
- **Auth-friendly**: basic HTTP auth + Selenium login path supported.

---

## Quick Start

### Requirements
- Python **3.10+**
- Google Chrome (for DOM XSS). Selenium ≥ **4.6** auto-manages ChromeDriver.

## Installation
Clone the repo and install in editable (dev) mode:

```bash
git clone https://github.com/eniat/fuzzer fuzzer
cd fuzzer
python -m venv .venv && source .venv/bin/activate 
pip install -U pip
pip install -e .
# the CLI entrypoint is now available as:
fuzz -h
```
## Running & Examples

### Full auto run

You may have to edit the selectors based on the login page of the webapp. That can be done here in default.yaml.
```yaml
  selectors:
    username_field: "login"
    password_field: "password"
    submit_name: "form"
  ```
Crawler + all fuzzers in sequence, with auth and full reporting:

```bash
fuzz https://target.tld --auth --username user --password password --login-path /login.php --swordlist sql --xwordlist XSS-Jhaddix --pwordlist LFI-Jhaddix --all --use-crawler --report-all --output-to-file
```

What happens:

1. Crawl endpoints & forms (headless by default).
2. Run **SQLi blind**, **SQLi content/error**, **XSS params**, **XSS forms**, **XSS DOM**, **XSS stored**, **path traversal**, then **param traversal**—in that order.
3. Deduplicate and print findings; optional JSON/file outputs if flags provided.

### Focused runs
>Extra wordlists can be uploaded into src/fuzzer/resources/wordlists and then used with any of the wordlist CLI commands and the shortened name without the .txt

**Path traversal only (with crawler)**

```bash
fuzz https://target.tld --use-crawler --pwordlist LFI-Jhaddix --fuzz-paths --report-all
```

**XSS – reflected in query params (with crawler)**

```bash
fuzz https://target.tld --use-crawler --xwordlist XSS-Jhaddix --xss-params
```

**XSS – forms only**

```bash
fuzz https://target.tld --use-crawler --xwordlist XSS-Jhaddix --xss-forms
```

**XSS – stored**

```bash
fuzz https://target.tld --use-crawler --xwordlist XSS-Jhaddix --xss-stored
```

**XSS – DOM (requires Chrome)**

```bash
fuzz https://target.tld --use-crawler --xwordlist XSS-Jhaddix --xss-dom
```

**SQLi – error/content-based**

```bash
fuzz https://target.tld --use-crawler --swordlist sql --fuzz-sqli
```

**SQLi – blind (boolean + timing with confirmation)**

```bash
fuzz https://target.tld --use-crawler --swordlist sql --fuzz-sqli-b
```

### Single-URL mode (no crawler)

When you **don’t** use `--use-crawler`, param fuzzers expect a **`FUZZ` placeholder** in your URL query:

**Param traversal (single URL)**

```bash
fuzz "https://target.tld/download?file=FUZZ" --pwordlist LFI-Jhaddix --fuzz-params
```

**XSS in params (single URL)**

```bash
fuzz "https://target.tld/search?q=FUZZ" --xwordlist XSS-Jhaddix --xss-params
```

> With the crawler enabled, the controller builds `?param=FUZZ` for you automatically. Without the crawler, you must include `FUZZ` yourself.

---

## Configuration

All runtime knobs come from `get_cfg()` which merges defaults and local overrides. Key areas used across the codebase:

```yaml
http:
  user_agent: "uni-fuzzer/0.1 (+https://example.local)"
  add_referer: true
  timeout_get_seconds: 5
  timeout_post_seconds: 5
  crawl_get: 5
  crawl_post: 5
  redirects:
    baseline_get: true
    baseline_post: true
    fuzz_get: false
    fuzz_post: false
    stored_xss: True
    submit: true
    
concurrency:
  max_workers: 10
  path_workers_recursive: 5
  threads_per_session: 2
  max_sessions_cap: 12

crawler:
  mode_default: "both"
  max_pages_default: 20
  rate_limit_default: 0.2
  headless_default: true
  output_to_file_default: false
  option_capacity: 80

xss: 
  dom_delay_seconds: 0.25
  stored_settle_seconds: 3
  regex:
    script: "<script[^>]*>(?:(?!</script>).)*({token})(?:(?!</script>).)*</script>"
    attr: "\\bon\\w+\\s*=\\s*(['\\\"]).*?({token}).*?\\1"
    jsurl: "(?:href|src)\\s*=\\s*(['\\\"])\\s*javascript:.*?({token}).*?\\1"
    html_comment: "<!--(?:(?!-->).)*{token}(?:(?!-->).)*-->"
    raw_html: "(?:^|>)[^<]*{token}[^<]*(?:<|$)"
  max_samples_per_group: 3
  
fuzz:
  max_depth_default: 3
  similarity_skip_threshold: 0.90
  baseline_404_path: "/thisshouldnotexist143903458903527903452"
  excluded_extensions: [".php", ".js", ".css", ".png", ".jpg", ".json"]

sqli:
  max_samples_per_group: 3
  timing_threshold_ms: 700
  blind_timing_factor: 2.0
  blind_time: 1
  timeout_blind: 120
  timing_baseline_probes: 3
  timing_payload_trials: 2
  timing_confirm_probes: 2
  plain_preprobe_min_delta: 1
  confirm_min_size_delta: 30

logging:
  format: "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
  json_format: '{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s","file":"%(filename)s","line":%(lineno)d}'
  date_format: "%Y-%m-%d %H:%M:%S"
```

> Tweak concurrency for stability. Network jitter can increase false positives in timing-based SQLi, the code already uses medians + confirmation probes to mitigate it.

---

## CLI Usage

Below are the most commonly used flags:

- Target & discovery
  - `--use-crawler`
  - `--crawler-mode (static, dynamic)`
  - `--max-pages N`
  - `--rate-limit FLOAT`
  - `--no-headless` (for Selenium runs)
- Wordlists
  - `--wordlist FILE` (fallback for all)
  - `--pwordlist FILE` (paths/params)
  - `--xwordlist FILE` (XSS)
  - `--swordlist FILE` (SQLi)
  - `--llm "prompt text..."` (filters the provided `--wordlist` via semantic similarity)
- Fuzzers (pick specific or `--all` to run in a safe sequence)
  - Paths: `--fuzz-paths`
  - Params: `--fuzz-params`
  - XSS: `--xss-params`, `--xss-forms`, `--xss-stored`, `--xss-dom`
  - SQLi: `--fuzz-sqli` (error/content), `--fuzz-sqli-b` (blind)
  - Everything: `--all`
- Output & behavior
  - `--output-to-file` (save console output to file too)
  - `--output-to-json` (emit machine-readable JSON)
  - `--report-all` (include “interesting” 200s and potential SQL)
  - `--bail-on-hit` (stop a given thread early on the first confirmed vulnerability)
- Auth
  - `--auth --username USER --password PASS --login-path /login`
- Logging
  - `--log` enable logging; plus `--log-level`, `--log-file`, `--log-console`, `--log-json`

---

## What Gets Reported

Findings are normalized and deduplicated by `collapseDuplicates`. Each finding follows a consistent shape:

```json
{
  "type": "xss_form | xss_param | xss_stored | xss_dom | sqli_inj | sqli_blind | sqli_potential | path | param | interesting | interesting_200",
  "url": "https://target.tld/some/path",
  "method": "GET | POST",
  "param": "q | id | ... (nullable)",
  "payload": "' OR 1=1 --",
  "indicator": "detected_sql_content | blind_sql_timing | dom_element_ctx | ...",
  "status_code": 200,
  "count": 1,
  "payload_samples": ["..."],
  "response_snippet": "<html>...</html>"
}
```

### Duplicate collapsing rules (high level)
- **Stored XSS** collapses by `(type, host, path, indicator)` and caps `payload_samples`.
- **Path/Param traversal** collapses by normalized path.
- The **highest** observed `status_code` within a group is preserved. Counts & unique samples are aggregated.

---

## Benchmark Results

This tool was evaluated against five established scanners (OWASP ZAP, SQLMap,
Dalfox, XSSer and wfuzz) across two deliberately vulnerable applications, DVWA
and bWAPP. Every tool ran under an identical, fully automated harness: the same
crawl-derived input set, containerised targets reset between runs, three runs per
tool per target, and manual replay to confirm each finding against a documented
ground-truth set.

The evaluation deliberately tested **unattended, scope-aligned automation** rather
than hand-tuned single-target runs. That framing matters for reading the numbers
below, and is discussed under "Why the baselines returned zero".

### Effectiveness (F1, higher is better)

| Class | Target | This tool | Best baseline | Baseline result |
|---|---|---|---|---|
| XSS | DVWA | **0.67** | 0.00 | ZAP / Dalfox / XSSer all 0 |
| XSS | bWAPP | **0.53** | 0.15 | Dalfox (precision 1.00, recall 0.08) |
| SQLi | DVWA | **0.80** | 0.00 | SQLMap / ZAP both 0 |
| SQLi | bWAPP | **0.55** | 0.00 | SQLMap / ZAP both 0 |
| Path traversal | DVWA | **1.00** | 0.00 | wfuzz / ZAP both 0 |
| Path traversal | bWAPP | **0.67** | 0.00 | wfuzz / ZAP both 0 |

This tool produced confirmed true positives across every class and both targets.
The baselines produced confirmed findings in only one cell of the table.

Recall is reported against the full documented ground truth, including
vulnerability instances outside this project's scope (DOM-based execution,
multi-step workflows). Against the in-scope subset the tool is built to detect,
recall is higher, so these figures are a conservative floor rather than a ceiling.
Because detection is wordlist-driven, recall is also bounded by payload coverage;
mutation-based generation (future work) would relax that.

### Where the baselines did better

Honesty matters more than a clean sweep here. On bWAPP XSS, **Dalfox achieved
perfect precision (1.00) against this tool's 0.90** it never raised a false
positive. It did so by reporting almost nothing: 2 findings against a ground truth
of 24, for a recall of 0.08. This tool detected 9, trading a single false positive
for far higher recall and a better F1 (0.53 vs 0.15). Which you prefer depends on
whether you are optimising for a quiet report or for coverage.

### Efficiency (time per confirmed vulnerability)

Raw runtime is misleading, because the fastest tools were fast partly by finding
nothing. ZAP finished a DVWA SQLi run in 38 seconds with zero true positives.
Time-per-true-positive is the fairer measure:

| Class | Target | This tool | Fastest baseline with TP > 0 |
|---|---|---|---|
| XSS | bWAPP | 0:15 | Dalfox, 5:00 |
| SQLi | bWAPP | 0:33 | none |
| XSS | DVWA | 0:41 | none |

This tool was rarely the fastest in wall-clock terms, but it was the only tool
returning confirmed findings quickly enough for the runtime to mean anything.

### Why the baselines returned zero

This is the most important caveat, and reading this section on it will
tell you more than the tables. The baselines were not run in their strongest
single-target configuration; they were run unattended across whole applications
under automation. Under those conditions:

- **Session and authentication handling dominated.** Cookies and sessions expired
  during longer runs even with repeated logins, cutting the baselines off from the
  vulnerable pages. This tool's integrated session management was built specifically
  to survive this, which is a large part of why it scored where the baselines did not.
- **Several tools are not designed for fully automated whole-app scanning** at this
  scale, and needed per-page invocation that limited concurrency.
- **Strict default confirmation** suppressed borderline findings in some baselines.

So these results should be read as **"an integrated pipeline with session handling
outperforms off-the-shelf scanners under unattended, scope-aligned automation"**,
not as a claim that this tool is a better vulnerability detector than SQLMap or ZAP
in absolute terms. Given a single target and manual configuration, a specialist tool
may well match or beat it.

### What this demonstrates

Integration. One pipeline spanning crawl, fuzz, confirm and report, with shared
session state meaningfully improves *practical* automated coverage across
multiple vulnerability classes, at a moderate runtime cost and with false positives
that are traceable to specific, documented causes.

---

## Performance Tips

- Keep `max_workers` and `threads_per_session` balanced, watch file descriptors and server rate limits.
- For SQLi blind timing, increase `timing_payload_trials` to improve confidence.
- Use `--bail-on-hit` for faster triage when breadth is more important than depth.
- DOM XSS runs a real browser; try `--no-headless` locally to debug.

---

## Security and Usage Notes

This project is intended for authorised security testing, local lab environments, and portfolio demonstration only.

Only run this tool against applications, systems, or networks that you own or have explicit permission to test. Do not use it against public websites, third-party services, university systems, employer systems, or production environments without written authorisation.

The fuzzer may generate high volumes of requests and may trigger security alerts, rate limits, logging, account lockouts, or application errors. Use conservative settings when testing and avoid running it against fragile or shared systems.

This tool is designed to support defensive security learning and web application testing. It should not be used for unauthorised vulnerability discovery, exploitation, disruption, data extraction, or any activity that could harm systems or users.

Any included payloads, wordlists, scanner integrations, or proof-of-concept checks are provided for controlled testing only. They are intended to help identify and understand common web application weaknesses such as injection flaws, traversal issues, and input validation problems in authorised environments.

The project is not hardened for deployment as a public service. It should be run locally or in a controlled lab environment only. Configuration files, target URLs, scan results, logs, and reports should be reviewed before committing to ensure they do not contain sensitive information.

The author is not responsible for misuse of this software. Users are responsible for ensuring that their testing complies with applicable laws, policies, and authorisation boundaries.

---

## License

This project is licensed under the MIT Licence. See the `LICENSE` file for details.
