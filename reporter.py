import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

_SEVERITY_ORDER = ["critical", "high", "medium", "low"]
_SEVERITY_BADGE = {
    "critical": "🔴 Critical",
    "high":     "🟠 High",
    "medium":   "🟡 Medium",
    "low":      "🟢 Low",
}


def generate_report(findings: list[dict], output_path: str = "./report.md") -> None:
    """Write a markdown security report to output_path."""
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []

    # ── Header ────────────────────────────────────────────────────────────────
    lines += [
        "# Security Vulnerability Report",
        "",
        f"**Generated:** {timestamp}  ",
        f"**Total findings:** {len(findings)}",
        "",
    ]

    # ── Summary table ─────────────────────────────────────────────────────────
    counts = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "medium")
        if sev in counts:
            counts[sev] += 1

    lines += [
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|------:|",
    ]
    for sev in _SEVERITY_ORDER:
        badge = _SEVERITY_BADGE[sev]
        lines.append(f"| {badge} | {counts[sev]} |")
    lines.append("")

    # ── Findings ──────────────────────────────────────────────────────────────
    lines.append("## Findings")
    lines.append("")

    if not findings:
        lines += ["_No vulnerabilities found._", ""]
        _write(lines, output_path)
        return

    by_severity: dict[str, list[dict]] = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "medium")
        by_severity.setdefault(sev, []).append(f)

    for sev in _SEVERITY_ORDER:
        group = by_severity.get(sev, [])
        if not group:
            continue

        badge = _SEVERITY_BADGE[sev]
        lines += [f"### {badge} ({len(group)})", ""]

        for idx, finding in enumerate(group, 1):
            file_ = finding.get("file", "unknown")
            line_no = finding.get("line_number", "?")
            vuln_type = finding.get("vulnerability_type", "Unknown")
            desc = finding.get("description", "")
            remediation = finding.get("remediation", "")

            lines += [
                f"#### {idx}. {vuln_type}",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **File** | `{file_}` |",
                f"| **Line** | {line_no} |",
                f"| **Severity** | {badge} |",
                "",
                f"**Description:** {desc}",
                "",
                f"**Remediation:** {remediation}",
                "",
                "---",
                "",
            ]

    _write(lines, output_path)


def _write(lines: list[str], output_path: str) -> None:
    path = Path(output_path)
    try:
        path.write_text("\n".join(lines), encoding="utf-8")
    except OSError as e:
        log.error("Failed to write report to %s: %s", output_path, e)
        raise
