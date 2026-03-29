import json
import logging
from pathlib import Path

import anthropic

log = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a security code reviewer specializing in Python application security. "
    "You identify vulnerabilities based on the OWASP Top 10. "
    "You MUST respond with ONLY a valid JSON array — no markdown, no preamble, no explanation. "
    "If you find no vulnerabilities, respond with exactly: []"
)

_USER_TEMPLATE = """\
Analyze the following Python file for security vulnerabilities.

Focus on these OWASP Top 10 categories:
- Injection (SQL, OS command, LDAP, XPath, template injection, etc.)
- Broken Authentication (weak credentials, insecure session management, missing rate limiting)
- Insecure Deserialization (pickle, yaml.load without Loader, marshal, etc.)
- Security Misconfiguration (debug mode enabled, default credentials, verbose error output)
- Sensitive Data Exposure (hardcoded secrets/API keys, logging PII, weak or missing encryption)

File: {filepath}

```python
{content}
```

Respond with ONLY a JSON array. Each element must have exactly these fields:
  "file"               – the filepath string shown above
  "line_number"        – integer line number of the vulnerability (best estimate)
  "vulnerability_type" – short label (e.g. "SQL Injection", "Hardcoded API Key")
  "severity"           – one of: "critical", "high", "medium", "low"
  "description"        – what the vulnerability is and why it is dangerous
  "remediation"        – concrete steps to fix it

Return ONLY the JSON array. No other text.\
"""

_REQUIRED_KEYS = frozenset(
    {"file", "line_number", "vulnerability_type", "severity", "description", "remediation"}
)
_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})


def analyze_file(
    client: anthropic.Anthropic, filepath: Path, content: str
) -> list[dict]:
    """Analyze a single Python file for vulnerabilities via the Claude API.

    Returns a (possibly empty) list of finding dicts on success, or [] on any
    API / parse error (after logging a warning).
    """
    prompt = _USER_TEMPLATE.format(filepath=str(filepath), content=content)

    try:
        with client.messages.stream(
            model="claude-opus-4-6",
            max_tokens=8192,
            thinking={"type": "enabled", "budget_tokens": 5000},
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        ) as stream:
            response = stream.get_final_message()
    except anthropic.AuthenticationError:
        raise  # let the caller surface this immediately
    except anthropic.APIError as e:
        log.warning("API error scanning %s: %s", filepath, e)
        return []

    # Locate the text block (thinking blocks come first with adaptive thinking)
    raw = ""
    for block in response.content:
        if block.type == "text":
            raw = block.text.strip()
            break

    if not raw:
        log.warning("Empty response for %s", filepath)
        return []

    # Strip accidental markdown fences
    if raw.startswith("```"):
        lines = raw.splitlines()
        end = len(lines) - 1 if lines[-1].strip() == "```" else len(lines)
        raw = "\n".join(lines[1:end])

    try:
        findings = json.loads(raw)
    except json.JSONDecodeError as e:
        log.warning("Could not parse JSON response for %s: %s", filepath, e)
        log.debug("Raw response snippet: %.500s", raw)
        return []

    if not isinstance(findings, list):
        log.warning("Unexpected response shape for %s (expected list)", filepath)
        return []

    validated = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        if not _REQUIRED_KEYS.issubset(item):
            log.debug("Skipping incomplete finding: %s", item)
            continue
        if item["severity"] not in _VALID_SEVERITIES:
            item["severity"] = "medium"
        validated.append(item)

    return validated
