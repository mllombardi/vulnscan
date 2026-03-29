"""vulnscan — scan Python codebases for security vulnerabilities using Claude AI."""

import argparse
import logging
import sys
from pathlib import Path

import anthropic

from scanner import find_python_files, read_file
from analyzer import analyze_file
from reporter import generate_report


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        level=logging.DEBUG if verbose else logging.INFO,
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="Scan Python files for OWASP Top 10 vulnerabilities using Claude AI.",
    )
    parser.add_argument(
        "path",
        help="Path to a Python file or directory to scan recursively.",
    )
    parser.add_argument(
        "--output",
        default="./report.md",
        metavar="FILE",
        help="Where to write the markdown report (default: ./report.md).",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug-level logging.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    _configure_logging(args.verbose)
    log = logging.getLogger(__name__)

    target = Path(args.path)
    if not target.exists():
        log.error("Path does not exist: %s", target)
        sys.exit(1)

    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env

    # ── Discover files ────────────────────────────────────────────────────────
    py_files = find_python_files(target)
    if not py_files:
        log.warning("No Python files found at: %s", target)
        sys.exit(0)

    log.info("Found %d Python file(s) to scan.", len(py_files))

    # ── Scan each file ────────────────────────────────────────────────────────
    all_findings: list[dict] = []

    for i, filepath in enumerate(py_files, 1):
        log.info("[%d/%d] Scanning %s", i, len(py_files), filepath)
        content = read_file(filepath)
        if content is None:
            continue  # error already logged in read_file

        try:
            findings = analyze_file(client, filepath, content)
        except anthropic.AuthenticationError:
            log.error(
                "Authentication failed. Make sure ANTHROPIC_API_KEY is set correctly."
            )
            sys.exit(1)

        log.info("  → %d finding(s)", len(findings))
        all_findings.extend(findings)

    # ── Report ────────────────────────────────────────────────────────────────
    log.info("Scan complete. Total findings: %d", len(all_findings))

    try:
        generate_report(all_findings, args.output)
    except OSError:
        sys.exit(1)  # error already logged in generate_report

    log.info("Report written to: %s", args.output)


if __name__ == "__main__":
    main()
