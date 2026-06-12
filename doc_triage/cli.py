from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

REQUIRED_TOOLS = ("rg", "rga", "trufflehog")
OPTIONAL_OCR_TOOLS = ("tesseract", "ocrmypdf", "pdftotext")


@dataclass(slots=True)
class ToolStatus:
    name: str
    path: str | None
    required: bool


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="doc-triage")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("doctor")

    scan = subparsers.add_parser("scan")
    scan.add_argument("target")
    scan.add_argument("--output", default="./report.md")
    scan.add_argument("--model", default="qwen3:8b")
    scan.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    scan.add_argument("--ocr", action="store_true")
    scan.add_argument("--max-files", type=int)
    scan.add_argument("--max-llm-files", type=int, default=30)
    scan.add_argument("--exclude", action="append", default=[])
    scan.add_argument("--no-llm", action="store_true")
    return parser


def detect_tools() -> list[ToolStatus]:
    statuses: list[ToolStatus] = []
    for name in REQUIRED_TOOLS:
        statuses.append(ToolStatus(name=name, path=shutil.which(name), required=True))
    for name in OPTIONAL_OCR_TOOLS:
        statuses.append(ToolStatus(name=name, path=shutil.which(name), required=False))
    statuses.append(ToolStatus(name="ollama", path=shutil.which("ollama"), required=False))
    return statuses


def run_doctor() -> int:
    statuses = detect_tools()
    missing_required = [tool.name for tool in statuses if tool.required and not tool.path]
    return EXIT_ERROR if missing_required else EXIT_OK


def write_report(path: Path, content: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def scan_target(target: Path, max_files: int | None) -> tuple[list[dict[str, str]], list[str]]:
    warnings: list[str] = []
    findings: list[dict[str, str]] = []
    text_extensions = {".txt", ".md", ".cfg", ".conf", ".log", ".ini", ".json", ".yaml", ".yml"}
    file_count = 0

    for file_path in sorted(target.rglob("*")):
        if not file_path.is_file():
            continue
        file_count += 1
        if max_files is not None and file_count > max_files:
            warnings.append(f"File limit reached at {max_files} files.")
            break
        if file_path.suffix.lower() not in text_extensions:
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            warnings.append(f"Could not read {file_path}: {exc}")
            continue
        for line_number, line in enumerate(content.splitlines(), start=1):
            lowered = line.lower()
            if any(token in lowered for token in ("password", "secret", "token", "apikey", "api_key")):
                findings.append(
                    {
                        "source": str(file_path),
                        "category": "credential",
                        "severity": "high",
                        "detector": "built-in",
                        "evidence": line,
                        "line": str(line_number),
                    }
                )
    return findings, warnings


def render_report(args: argparse.Namespace, target: Path, findings: list[dict[str, str]], warnings: list[str]) -> str:
    generated_at = datetime.now(timezone.utc).isoformat()
    lines = [
        "# Sensitive Report",
        "",
        "This report may contain verbatim secrets and should be handled carefully.",
        "",
        "## Scope",
        f"- Target: {target}",
        f"- Generated: {generated_at}",
        f"- Model: {args.model}",
        f"- OCR Enabled: {'yes' if args.ocr else 'no'}",
        "",
        "## Coverage and Warnings",
    ]
    if warnings:
        lines.extend(f"- {warning}" for warning in warnings)
    else:
        lines.append("- No scanner warnings.")

    lines.extend(["", "## Executive Summary"])
    if findings:
        lines.append(f"- Found {len(findings)} high-signal lines for manual review.")
    else:
        lines.append("- No high-signal findings detected by the deterministic scanner.")

    lines.extend(["", "## Ranked High-Value Findings"])
    if findings:
        for finding in findings:
            lines.append(
                f"- [{finding['severity']}] {finding['category']} in {finding['source']}:{finding['line']} via {finding['detector']}"
            )
            lines.append(f"  Evidence: `{finding['evidence']}`")
    else:
        lines.append("- None.")

    lines.extend(["", "## Secret and Credential Findings"])
    lines.append("- See ranked findings above.")
    lines.extend(["", "## Personal and Financial Data Findings"])
    lines.append("- None.")
    lines.extend(["", "## Interesting Documents and Relationships"])
    lines.append("- None.")
    lines.extend(["", "## Files Recommended for Manual Review"])
    if findings:
        for source in sorted({finding["source"] for finding in findings}):
            lines.append(f"- {source}")
    else:
        lines.append("- None.")
    lines.append("")
    return "\n".join(lines)


def run_scan(args: argparse.Namespace) -> int:
    target = Path(args.target).expanduser().resolve()
    if not target.exists() or not target.is_dir():
        return EXIT_ERROR

    findings, warnings = scan_target(target, args.max_files)
    report = render_report(args, target, findings, warnings)
    write_report(Path(args.output).expanduser(), report)

    statuses = detect_tools()
    missing_required = [tool.name for tool in statuses if tool.required and not tool.path]
    return EXIT_ERROR if missing_required or warnings else EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command is None:
        return EXIT_USAGE
    if args.command == "doctor":
        return run_doctor()
    if args.command == "scan":
        return run_scan(args)
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
