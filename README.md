# Uni Fuzzer

Web fuzzing toolkit with **crawlers** (both dynamic and static) and focused fuzzers for **Path Traversal**, **XSS** (params, forms, stored, DOM), and **SQL Injection** (error/content-based and blind timing/boolean).

---

## To‑Do List

- [x] **Remove imports of concrete classes**  
  Remove the imports of my own concrete classes and make them go via an adapter/ interfaces / Services

- [ ] **Add return/ parameters annotations to functions**  
  Add return/ parameters annotations to functions to give greater understanding.

- [ ] **Add a domain scope to target fuzzing**  
  Add a scope that the crawlers and fuzzers stay inside for more refined fuzzing.

- [ ] **Add tests**  
  pytests folder that includes tests for multiple functions and the whole thing.

- [ ] **Config validation**  
  UIsing pydantic implement a config validation to make sure whats given is correct.

- [ ] **Implement mutations**  
  Start and build custom mutation strategies.

- [ ] **Improve CLI UX**  
  Add CLI art, loading animations, and progress bars.

- [ ] **Explore OpenAI prompting**  
  Integrate LLM prompting depending on cost and time.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [CLI Usage](#cli-usage)
- [What Gets Reported](#what-gets-reported)
- [Architecture](#architecture)
- [Performance Tips](#performance-tips)

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
git clone https://github.com/eniat/fuzzer uni_fuzzer
cd uni_fuzzer
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
fuzz https://target.tld --auth --username user --password password --login-path /login.php --swordlist sql --xwordlist XSS-Jhaddix --pwordlist LFI-Jhaddix--all --use-crawler --report-all --output-to-file
```

What happens:

1. Crawl endpoints & forms (headless by default).
2. Run **SQLi blind**, **SQLi content/error**, **XSS params**, **XSS forms**, **XSS DOM**, **XSS stored**, **path traversal**, then **param traversal**—in that order.
3. Deduplicate and print findings; optional JSON/file outputs if flags provided.

### Focused runs
>Extra wordlists can be uploaded into src/uni_fuzzer/resources/wordlists and then used with any of the wordlist CLI commands and the shortened name without the .txt

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
  - `--report-to-json` (emit machine-readable JSON)
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

## Architecture

- `crawler/` → discovers endpoints & forms.
- `fuzzers/path.py` → path traversal + recursion into interesting 200s.
- `fuzzers/xss.py` → reflected/stored/DOM XSS with tokenized canaries and DOM probes.
- `fuzzers/sqli.py` → content/error SQLi + blind boolean/timing with confirmation.
- `core/baseline.py` → baselines for comparators (XSS forms, SQLi, timing baselines).
- `core/probes.py` → reflexivity/DOM reactivity probes.
- `core/utility.py` → config, wordlists, helpers, duplicate collapsing.
- `core/reporting.py` → `Finding` model + pretty/JSON reporting.
- `auth/auth.py` → session login + Selenium login helpers.
- `controller` (`run(args)`) → orchestrates phases, session pools, and output.

Threading is used throughout via `ThreadPoolExecutor`, concurrency is controlled centrally from config.

---

## Performance Tips

- Keep `max_workers` and `threads_per_session` balanced, watch file descriptors and server rate limits.
- For SQLi blind timing, increase `timing_payload_trials` to improve confidence.
- Use `--bail-on-hit` for faster triage when breadth is more important than depth.
- DOM XSS runs a real browser; try `--no-headless` locally to debug.

---