from __future__ import annotations

import fnmatch
import html
import json
import re
from pathlib import Path
from typing import Sequence

from .constants import (
    DOC_NOISE_FILENAMES,
    NOISE_PATTERNS,
    NOISE_PHRASES,
    SEVERITY_ORDER,
    SIGNAL_PATTERN_LABELS,
    SIGNAL_PATTERNS,
    SENSITIVE_FILENAMES,
)
from .models import Finding


def severity_rank(value: str) -> int:
    return SEVERITY_ORDER.get(value, 0)


def is_valid_bsn(value: str) -> bool:
    digits = "".join(char for char in value if char.isdigit())
    if len(digits) != 9:
        return False
    total = sum(int(digit) * factor for digit, factor in zip(digits[:8], range(9, 1, -1), strict=True))
    total -= int(digits[-1])
    return total % 11 == 0


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


def is_noise_evidence(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return True
    if sum(char.isalnum() for char in stripped) < 3:
        return True
    punctuation = sum(not char.isalnum() and not char.isspace() for char in stripped)
    return punctuation >= max(4, len(stripped) - punctuation)


def classify_match(text: str, source: str = "") -> tuple[str, str, float] | None:
    if is_noise_evidence(text):
        return None

    stripped = text.strip()
    lowered = stripped.lower()
    source_name = Path(source).name.lower() if source else ""

    for pattern in NOISE_PATTERNS:
        if pattern.search(stripped):
            return None

    for pattern, rule in SIGNAL_PATTERNS:
        if pattern.search(stripped):
            return rule

    if stripped.startswith(("http://", "https://")):
        return None
    if source_name in DOC_NOISE_FILENAMES:
        return None
    if any(phrase in lowered for phrase in NOISE_PHRASES):
        return None
    return None


def classify_match_with_detector(text: str, source: str = "") -> tuple[str, str, float, str] | None:
    if is_noise_evidence(text):
        return None

    stripped = text.strip()
    lowered = stripped.lower()
    source_name = Path(source).name.lower() if source else ""

    for pattern in NOISE_PATTERNS:
        if pattern.search(stripped):
            return None

    for index, (pattern, rule) in enumerate(SIGNAL_PATTERNS):
        if pattern.search(stripped):
            return (*rule, SIGNAL_PATTERN_LABELS[index])

    if stripped.startswith(("http://", "https://")):
        return None
    if source_name in DOC_NOISE_FILENAMES:
        return None
    if any(phrase in lowered for phrase in NOISE_PHRASES):
        return None
    return None


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


def extract_digit_runs(text: str) -> list[str]:
    return re.findall(r"\b\d{9}\b", text)


def contextual_credential_candidate(line: str, previous_lines: Sequence[str]) -> Finding | None:
    lowered_context = " ".join(previous.lower() for previous in previous_lines[-3:])
    if not any(marker in lowered_context for marker in ("do not share", "integration settings", "session established", "login")):
        return None
    match = re.search(r":\s*([A-Za-z][A-Za-z0-9_-]{7,})\s*$", line)
    if not match:
        return None
    candidate = match.group(1)
    if "." in candidate or "/" in candidate:
        return None
    if not any(char.isdigit() for char in candidate):
        return None
    if "-" not in candidate and "_" not in candidate:
        return None
    return Finding(
        source="",
        category="credential",
        severity="high",
        detector="contextual-ocr-credential",
        evidence=line,
        line=None,
        confidence=0.88,
        metadata={"candidate": candidate},
    )


def keyword_findings(target: Path, file_path: Path, content: str) -> list[Finding]:
    findings: list[Finding] = []
    invalid_bsn_context = False
    previous_lines: list[str] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        lowered_line = line.lower()
        if any(marker in lowered_line for marker in ("invalid bsn", "bsn for testing", "test user sandbox", "sandbox")):
            invalid_bsn_context = True
        classification = classify_match_with_detector(line, relative_source(target, file_path))
        if classification is not None:
            category, severity, confidence, detector = classification
            if detector == "pattern:bsn-keyword" and any(
                marker in lowered_line for marker in ("invalid", "testing", "sandbox", "sample", "dummy", "fake")
            ):
                continue
            findings.append(
                Finding(
                    source=relative_source(target, file_path),
                    category=category,
                    severity=severity,
                    detector=detector,
                    evidence=line,
                    line=line_number,
                    confidence=confidence,
                    metadata={},
                )
            )
        else:
            contextual = contextual_credential_candidate(line, previous_lines)
            if contextual is not None:
                contextual.source = relative_source(target, file_path)
                contextual.line = line_number
                findings.append(contextual)
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
                if invalid_bsn_context or any(
                    marker in lowered_line
                    for marker in ("invalid", "testing", "sandbox", "sample", "dummy", "fake", "test user")
                ):
                    continue
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
        previous_lines.append(line)
    return findings


def should_exclude(target: Path, file_path: Path, exclude_globs: Sequence[str]) -> bool:
    relative = relative_source(target, file_path)
    return any(fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(file_path.name, pattern) for pattern in exclude_globs)


def glob_to_regex(pattern: str) -> str:
    escaped: list[str] = []
    for char in pattern:
        if char == "*":
            escaped.append(".*")
        elif char == "?":
            escaped.append(".")
        else:
            escaped.append(re.escape(char))
    return "".join(escaped)


def rga_exclude_globs(pattern: str) -> list[str]:
    if pattern.startswith("*/"):
        suffix = pattern[2:]
        return [f"**/{suffix}", suffix]
    return [pattern]


def is_ignorable_rga_failure(result: object) -> bool:
    exit_code = getattr(result, "exit_code", None)
    stderr = getattr(result, "stderr", "").lower()
    return exit_code == 2 and (
        "preprocessor command failed" in stderr or "error: during preprocessing" in stderr
    )


def parse_rga_output(payload: str, target: Path) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    warnings: list[str] = []
    for raw_line in payload.splitlines():
        if not raw_line.strip():
            continue
        try:
            record = json.loads(raw_line)
        except json.JSONDecodeError:
            warnings.append("Malformed rga JSON record.")
            continue
        if record.get("type") != "match":
            continue
        data = record.get("data", {})
        source = data.get("path", {}).get("text", "")
        evidence = data.get("lines", {}).get("text", "").rstrip("\n")
        line = data.get("line_number")
        classification = classify_match(evidence, source)
        if classification is None:
            continue
        category, severity, confidence = classification
        findings.append(
            Finding(
                source=relative_source(target, Path(source)) if source else "<unknown>",
                category=category,
                severity=severity,
                detector="rga",
                evidence=evidence,
                line=line,
                confidence=confidence,
                metadata={},
            )
        )
    return findings, warnings


def parse_trufflehog_output(payload: str, target: Path) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    warnings: list[str] = []
    for raw_line in payload.splitlines():
        if not raw_line.strip():
            continue
        try:
            record = json.loads(raw_line)
        except json.JSONDecodeError:
            warnings.append("Malformed trufflehog JSON record.")
            continue
        source = (
            record.get("SourceMetadata", {})
            .get("Data", {})
            .get("Filesystem", {})
            .get("file", "<unknown>")
        )
        detector = str(record.get("DetectorName", "trufflehog"))
        raw_value = str(record.get("Raw", "")).strip()
        severity = "critical" if record.get("Verified") else "high"
        findings.append(
            Finding(
                source=relative_source(target, Path(source)) if source else "<unknown>",
                category="credential",
                severity=severity,
                detector="trufflehog",
                evidence=raw_value or detector,
                line=None,
                confidence=0.99 if record.get("Verified") else 0.85,
                metadata={"detector_name": detector},
            )
        )
    return findings, warnings
