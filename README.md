# vulnscan

A Python CLI tool that scans Python codebases for security vulnerabilities using the Claude AI API. It analyzes each `.py` file against the OWASP Top 10 and produces a structured Markdown report.

---

## How it works

```
your code
    │
    ▼
scanner.py          Recursively finds all .py files in the target path
    │
    ▼
analyzer.py         Sends each file to Claude (claude-opus-4-6) with a
                    security-focused prompt. Claude returns a JSON array
                    of findings per file.
    │
    ▼
reporter.py         Aggregates all findings and writes report.md,
                    grouped by severity (critical → high → medium → low).
```

### What Claude looks for

The prompt instructs Claude to focus on these five OWASP Top 10 categories:

| Category | Examples |
|----------|---------|
| **Injection** | SQL injection, OS command injection, template injection (SSTI), LDAP injection |
| **Broken Authentication** | Hardcoded credentials, weak session secrets, missing rate limiting, predictable tokens |
| **Insecure Deserialization** | `pickle.loads` on untrusted data, `yaml.load` without `Loader`, `marshal.loads` |
| **Security Misconfiguration** | `DEBUG=True` in production, verbose error responses, exposed environment variables |
| **Sensitive Data Exposure** | Hardcoded API keys/secrets, logging PII, disabled TLS verification, weak crypto (MD5, SHA1, XOR) |

Each finding includes:
- **File** and **line number**
- **Vulnerability type** (e.g. "SQL Injection", "Hardcoded API Key")
- **Severity** — `critical`, `high`, `medium`, or `low`
- **Description** — what the vulnerability is and why it is dangerous
- **Remediation** — concrete steps to fix it

---

## Project structure

```
vulnscan/
├── vulnscan.py       # CLI entrypoint — argparse, orchestration, error handling
├── scanner.py        # File discovery and safe file reading
├── analyzer.py       # Claude API integration, prompt building, JSON parsing
├── reporter.py       # Markdown report generation
├── requirements.txt  # Python dependencies
└── test/             # Sample vulnerable files for testing
    ├── db_utils.py       SQL injection, hardcoded DB credentials, PII logging
    ├── auth.py           Broken auth, weak crypto (MD5), predictable tokens
    ├── file_handler.py   OS command injection, path traversal, debug mode
    ├── serializer.py     Insecure deserialization (pickle, yaml, marshal)
    ├── api_client.py     Hardcoded API keys, disabled TLS, weak hashing
    └── config.py         Security misconfiguration, SSTI, exposed env vars
```

---

## Prerequisites

- Python 3.10 or later
- An [Anthropic API key](https://console.anthropic.com/)

---

## Installation

**1. Clone or download the repository**

```bash
git clone <repo-url>
cd vulnscan
```

**2. Create and activate a virtual environment** *(recommended)*

```bash
python -m venv .venv

# macOS / Linux
source .venv/bin/activate

# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Windows (cmd)
.venv\Scripts\activate.bat
```

**3. Install dependencies**

```bash
pip install -r requirements.txt
```

**4. Set your Anthropic API key**

```bash
# macOS / Linux
export ANTHROPIC_API_KEY="sk-ant-..."

# Windows (PowerShell)
$env:ANTHROPIC_API_KEY = "sk-ant-..."

# Windows (cmd)
set ANTHROPIC_API_KEY=sk-ant-...
```

> The key is read from the environment. Never hardcode it in your code.

---

## Usage

```
python vulnscan.py <path> [--output FILE] [-v]
```

| Argument | Description | Default |
|----------|-------------|---------|
| `path` | Path to a `.py` file or a directory to scan recursively | *(required)* |
| `--output FILE` | Where to write the Markdown report | `./report.md` |
| `-v` / `--verbose` | Enable debug-level log output | off |

### Examples

**Scan the bundled test folder:**
```bash
python vulnscan.py test/
```

**Scan a single file:**
```bash
python vulnscan.py test/db_utils.py
```

**Scan your own project and save the report elsewhere:**
```bash
python vulnscan.py /path/to/your/project --output /tmp/security-report.md
```

**Verbose mode (shows debug output and raw API responses on parse errors):**
```bash
python vulnscan.py test/ -v
```

---

## Sample output

After scanning the `test/` folder you will see terminal output similar to:

```
10:42:01 [INFO] Found 6 Python file(s) to scan.
10:42:01 [INFO] [1/6] Scanning test/api_client.py
10:42:09 [INFO]   → 7 finding(s)
10:42:09 [INFO] [2/6] Scanning test/auth.py
10:42:17 [INFO]   → 6 finding(s)
...
10:43:12 [INFO] Scan complete. Total findings: 28
10:43:12 [INFO] Report written to: ./report.md
```

And `report.md` will look like:

```markdown
# Security Vulnerability Report

**Generated:** 2026-03-29 10:43 UTC
**Total findings:** 28

## Summary

| Severity  | Count |
|-----------|------:|
| 🔴 Critical |     9 |
| 🟠 High     |    11 |
| 🟡 Medium   |     6 |
| 🟢 Low      |     2 |

## Findings

### 🔴 Critical (9)

#### 1. SQL Injection

| Field    | Value                        |
|----------|------------------------------|
| **File** | `test/db_utils.py`           |
| **Line** | 27                           |
| **Severity** | 🔴 Critical              |

**Description:** User input is concatenated directly into a SQL query string...

**Remediation:** Use parameterized queries (`cursor.execute(query, (username,))`)...
```

---

## Error handling

| Situation | Behaviour |
|-----------|-----------|
| `ANTHROPIC_API_KEY` missing or invalid | Exits immediately with a clear error message |
| A file cannot be read (permissions, encoding) | Logs a warning, skips that file, continues |
| Claude returns a non-JSON response | Logs a warning, skips that file, continues |
| Claude returns an incomplete finding (missing fields) | Finding is silently dropped |
| Severity value is unexpected | Normalised to `"medium"` |
| Output file cannot be written | Logs an error and exits with code 1 |

---

## Cost and performance

Each file is sent as a separate API call to `claude-opus-4-6`.

| Factor | Detail |
|--------|--------|
| Model | `claude-opus-4-6` with adaptive thinking |
| Pricing | ~$5 / 1M input tokens, ~$25 / 1M output tokens |
| Typical file | A 100-line Python file uses roughly 1,000–2,000 input tokens |
| `max_tokens` per call | 8,192 (output cap per file) |

For a project with 50 files averaging 150 lines each, expect roughly **$0.50–$2.00** and **2–5 minutes** of wall-clock time.

To reduce cost on large codebases, consider filtering to only scan files that have changed since the last run, or exclude test/vendor directories.

---

## Limitations

- Only scans `.py` files — other languages are not supported
- Line numbers are Claude's best estimates; they may be off by a few lines
- False positives are possible — always review findings before acting on them
- Large files (>1,000 lines) may occasionally hit the `max_tokens` output cap; increase it in `analyzer.py` if needed
- vulnscan is a static analysis aid, not a substitute for a full security audit

## Roadmap

![Vulnscan roadmap](docs/roadmap.svg)

| Version | Name | What it does |
|---|---|---|
| **V1** | Pipeline scanner | Read files → Claude API → markdown report |
| **V2** | Smarter pipeline | Bandit pre-filter, chunked processing, severity scoring, HTML report, multi-language |
| **V3** | CI/CD integration | GitHub Action, PR comment annotations, badge, baseline diffs, fail-on-critical |
| **V4** | Agentic scanner | Claude drives the loop via tool use — follows import chains, requests context autonomously |
| **V5** | MCP server | Expose vulnscan as an MCP tool, plug directly into Claude Code and other agents |
| **V6** | Platform | Web dashboard, trend tracking, SARIF export, AI-generated remediation PRs |

> V4 is the architectural inflection point — below it, your Python script
> orchestrates Claude. Above it, Claude orchestrates itself.
