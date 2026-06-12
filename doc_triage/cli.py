from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

REQUIRED_TOOLS = ("rg", "rga", "trufflehog")
OPTIONAL_OCR_TOOLS = ("tesseract", "ocrmypdf", "pdftotext")
TEXT_EXTENSIONS = {".txt", ".md", ".cfg", ".conf", ".log", ".ini", ".json", ".yaml", ".yml", ".csv"}
SENSITIVE_FILENAMES = {
    ".env": ("credential", "high"),
    "id_rsa": ("sensitive-file", "critical"),
    "id_dsa": ("sensitive-file", "critical"),
    "credentials.txt": ("credential", "high"),
    "secrets.txt": ("credential", "high"),
    "config.ovpn": ("sensitive-file", "medium"),
}
KEYWORD_RULES = {
    "password": ("credential", "high", 0.95),
    "secret": ("credential", "high", 0.9),
    "token": ("credential", "high", 0.9),
    "apikey": ("credential", "high", 0.9),
    "api_key": ("credential", "high", 0.9),
    "bearer ": ("credential", "high", 0.9),
    "iban": ("financial-data", "medium", 0.7),
    "bsn": ("personal-data", "medium", 0.7),
}
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass(slots=True)
class ToolStatus:
    name: str
    path: str | None
    required: bool


@dataclass(slots=True)
class Finding:
    source: str
    category: str
    severity: str
    detector: str
    evidence: str
    line: int | None
    confidence: float
    metadata: dict[str, str] = field(default_factory=dict)


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


def is_valid_bsn(value: str) -> bool:
    digits = "".join(char for char in value if char.isdigit())
    if len(digits) != 9:
        return False
    total = sum(int(digit) * factor for digit, factor in zip(digits[:8], range(9, 1, -1), strict=True))
    total -= int(digits[-1])
    return total % 11 == 0


def write_report(path: Path, content: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def severity_rank(value: str) -> int:
    return SEVERITY_ORDER.get(value, 0)


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    deduped: dict[tuple[str, str, str], Finding] = {}
    for finding in findings:
        key = (finding.source, finding.category, finding.evidence.strip().lower())
        current = deduped.get(key)
        if current is None:
            deduped[key] = finding
            continue
        if severity_rank(finding.severity) > severity_rank(current.severity):
            deduped[key] = finding
            continue
        if severity_rank(finding.severity) == severity_rank(current.severity) and finding.confidence > current.confidence:
            deduped[key] = finding
    return sorted(
        deduped.values(),
        key=lambda finding: (-severity_rank(finding.severity), finding.source, finding.line or 0, finding.evidence),
    )


def relative_source(target: Path, file_path: Path) -> str:
    try:
        return str(file_path.relative_to(target))
    except ValueError:
        return str(file_path)


def filename_finding(target: Path, file_path: Path) -> Finding | None:
    rule = SENSITIVE_FILENAMES.get(file_path.name.lower())
    if rule is None:
        return None
    category, severity = rule
    return Finding(
        source=relative_source(target, file_path),
        category=category,
        severity=severity,
        detector="filename-rule",
        evidence=file_path.name,
        line=None,
        confidence=0.8,
        metadata={},
    )


def keyword_findings(target: Path, file_path: Path, content: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        lowered = line.lower()
        for token, (category, severity, confidence) in KEYWORD_RULES.items():
            if token in lowered:
                findings.append(
                    Finding(
                        source=relative_source(target, file_path),
                        category=category,
                        severity=severity,
                        detector="built-in",
                        evidence=line,
                        line=line_number,
                        confidence=confidence,
                        metadata={},
                    )
                )
        for candidate in extract_digit_runs(line):
            if is_valid_bsn(candidate):
                findings.append(
                    Finding(
                        source=relative_source(target, file_path),
                        category="personal-data",
                        severity="high",
                        detector="bsn-validator",
                        evidence=line,
                        line=line_number,
                        confidence=0.95,
                        metadata={"bsn": candidate, "validation": "valid"},
                    )
                )
            elif len(candidate) == 9:
                findings.append(
                    Finding(
                        source=relative_source(target, file_path),
                        category="personal-data",
                        severity="low",
                        detector="bsn-candidate",
                        evidence=line,
                        line=line_number,
                        confidence=0.3,
                        metadata={"bsn": candidate, "validation": "candidate"},
                    )
                )
    return findings


def extract_digit_runs(text: str) -> list[str]:
    values: list[str] = []
    current: list[str] = []
    for char in text:
        if char.isdigit():
            current.append(char)
        else:
            if current:
                values.append("".join(current))
            current = []
    if current:
        values.append("".join(current))
    return values


def scan_target(target: Path, max_files: int | None) -> tuple[list[Finding], list[str]]:
    warnings: list[str] = []
    findings: list[Finding] = []
    file_count = 0

    for file_path in sorted(target.rglob("*")):
        if not file_path.is_file():
            continue
        file_count += 1
        if max_files is not None and file_count > max_files:
            warnings.append(f"File limit reached at {max_files} files.")
            break

        sensitive = filename_finding(target, file_path)
        if sensitive is not None:
            findings.append(sensitive)

        if file_path.suffix.lower() not in TEXT_EXTENSIONS and file_path.name.lower() not in SENSITIVE_FILENAMES:
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            warnings.append(f"Could not read {file_path}: {exc}")
            continue
        findings.extend(keyword_findings(target, file_path, content))

    return deduplicate_findings(findings), warnings


def render_report(args: argparse.Namespace, target: Path, findings: list[Finding], warnings: list[str]) -> str:
    generated_at = datetime.now(timezone.utc).isoformat()
    high_value = [finding for finding in findings if severity_rank(finding.severity) >= severity_rank("high")]
    secret_findings = [finding for finding in findings if finding.category in {"credential", "sensitive-file"}]
    personal_financial = [finding for finding in findings if finding.category in {"personal-data", "financial-data"}]

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
        lines.append(f"- Found {len(findings)} findings across {len({finding.source for finding in findings})} files.")
    else:
        lines.append("- No high-signal findings detected by the deterministic scanner.")

    lines.extend(["", "## Ranked High-Value Findings"])
    lines.extend(render_findings(high_value or findings))

    lines.extend(["", "## Secret and Credential Findings"])
    lines.extend(render_findings(secret_findings))

    lines.extend(["", "## Personal and Financial Data Findings"])
    lines.extend(render_findings(personal_financial))

    lines.extend(["", "## Interesting Documents and Relationships"])
    if findings:
        lines.append("- Manual review should start with the highest-severity files listed below.")
    else:
        lines.append("- None.")

    lines.extend(["", "## Files Recommended for Manual Review"])
    if findings:
        for source in sorted({finding.source for finding in findings}):
            lines.append(f"- {source}")
    else:
        lines.append("- None.")

    lines.append("")
    return "\n".join(lines)


def render_findings(findings: list[Finding]) -> list[str]:
    if not findings:
        return ["- None."]
    lines: list[str] = []
    for finding in findings:
        location = f"{finding.source}:{finding.line}" if finding.line is not None else finding.source
        lines.append(f"- [{finding.severity}] {finding.category} in {location} via {finding.detector}")
        lines.append(f"  Evidence: `{finding.evidence}`")
    return lines


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
