from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from .constants import NON_FATAL_WARNING_PREFIXES, SEVERITY_ORDER
from .detectors import severity_rank
from .models import AgentRun, Finding
from .runtime import colorize


def summarize_evidence(text: str, limit: int = 120) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def summarize_findings(
    findings: list[Finding],
    warnings: list[str],
    agent_run: AgentRun | None = None,
) -> list[str]:
    by_severity = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

    lines = [
        colorize("Scan Summary", "info"),
        f"  Findings: {len(findings)}  Warnings: {len(warnings)}",
        "  Severity: "
        + ", ".join(
            f"{colorize(severity, severity)}={by_severity[severity]}"
            for severity in ("critical", "high", "medium", "low")
            if by_severity.get(severity, 0)
        ),
    ]

    if warnings:
        lines.append(f"  {colorize('Warnings', 'warning')}:")
        for warning in warnings[:5]:
            lines.append(f"    - {warning}")

    ranked = sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_ORDER.get(finding.severity, 0),
            -finding.confidence,
            finding.source,
            finding.line or -1,
        ),
    )
    if ranked:
        lines.append("  Top findings:")
        for finding in ranked[:5]:
            location = f"{finding.source}:{finding.line}" if finding.line is not None else finding.source
            lines.append(
                f"    - {colorize(finding.severity, finding.severity)} {location} [{finding.category}] via {finding.detector}"
            )
            lines.append(f"      Evidence: {summarize_evidence(finding.evidence)}")
    if agent_run is not None:
        confirmed = sum(1 for item in agent_run.hypotheses if item.status == "confirmed")
        lines.append(
            f"  Agent mode: actions={len(agent_run.actions)} observations={len(agent_run.observations)} "
            f"confirmed_hypotheses={confirmed}"
        )
        if agent_run.warnings:
            for warning in agent_run.warnings[:3]:
                lines.append(f"    - {warning}")
        for observation in agent_run.observations[:3]:
            label = observation.derived_claim or observation.source_mechanism
            lines.append(f"    - {observation.path} [{label}]")
            lines.append(f"      Evidence: {summarize_evidence(observation.evidence)}")
    return lines


def is_fatal_warning(warning: str) -> bool:
    return not any(warning.startswith(prefix) for prefix in NON_FATAL_WARNING_PREFIXES)


def looks_like_source_path(value: object) -> bool:
    if not isinstance(value, str):
        return False
    candidate = value.strip()
    if not candidate:
        return False
    if candidate[:1].isdigit() and ". " in candidate:
        return False
    return "/" in candidate or "." in Path(candidate).name


def render_priority_item(item: object) -> str:
    if isinstance(item, dict):
        source = item.get("source") or item.get("source_path") or "<source missing>"
        reason = (
            item.get("why")
            or item.get("description")
            or item.get("claim")
            or item.get("rationale")
            or item.get("context")
            or item.get("supporting_evidence")
            or "<reason missing>"
        )
        if reason == "<reason missing>":
            return ""
        return f"- {source}: {reason}".rstrip()
    return f"- {item}"


def render_relationship(item: object) -> list[str]:
    if isinstance(item, dict):
        relation_type = str(item.get("type") or item.get("relationship_type") or "relationship")
        description = str(item.get("description") or item.get("inference") or "").strip()
        sources = item.get("source_paths")
        if not sources and item.get("source_path"):
            sources = [item.get("source_path")]
        if not description and not sources:
            return []
        lines = [f"- {relation_type}: {description}".rstrip()]
        if isinstance(sources, list) and sources:
            lines.append(f"  Sources: {', '.join(str(source) for source in sources)}")
        return lines
    return [f"- {item}"]


def normalize_llm_summary(summary: dict[str, object]) -> dict[str, object]:
    priority_findings = summary.get("priority_findings")
    review_order = summary.get("review_order")
    if not isinstance(priority_findings, list) or not isinstance(review_order, list):
        return summary

    normalized_items: list[object] = []
    for index, item in enumerate(priority_findings):
        if isinstance(item, dict) and not item.get("source") and not item.get("source_path"):
            if index < len(review_order) and isinstance(review_order[index], str) and review_order[index].strip():
                updated_item = dict(item)
                updated_item["source_path"] = review_order[index]
                normalized_items.append(updated_item)
                continue
        normalized_items.append(item)

    normalized_summary = dict(summary)
    normalized_summary["priority_findings"] = normalized_items
    return normalized_summary


def render_findings(findings: list[Finding]) -> list[str]:
    if not findings:
        return ["- None."]
    lines: list[str] = []
    for finding in findings:
        location = f"{finding.source}:{finding.line}" if finding.line is not None else finding.source
        lines.append(f"- [{finding.severity}] {finding.category} in {location} via {finding.detector}")
        lines.append(f"  Evidence: `{finding.evidence}`")
    return lines


def render_report(
    args: argparse.Namespace,
    target: Path,
    findings: list[Finding],
    warnings: list[str],
    llm_summary: dict[str, object] | None = None,
    agent_run: AgentRun | None = None,
) -> str:
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
    if llm_summary and llm_summary.get("executive_summary"):
        lines.append(f"- {llm_summary['executive_summary']}")
    elif findings:
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
    if llm_summary and llm_summary.get("relationships"):
        for relationship in llm_summary["relationships"]:
            lines.extend(render_relationship(relationship))
    elif findings:
        lines.append("- Manual review should start with the highest-severity files listed below.")
    else:
        lines.append("- None.")

    if llm_summary and llm_summary.get("priority_findings"):
        lines.extend(["", "## LLM Priority Findings"])
        for item in llm_summary["priority_findings"]:
            rendered_item = render_priority_item(item)
            if rendered_item:
                lines.append(rendered_item)

    lines.extend(["", "## Files Recommended for Manual Review"])
    review_order = llm_summary.get("review_order") if llm_summary else None
    if isinstance(review_order, list) and review_order and all(looks_like_source_path(source) for source in review_order):
        for source in review_order:
            lines.append(f"- {source}")
    elif findings:
        for source in sorted({finding.source for finding in findings}):
            lines.append(f"- {source}")
    else:
        lines.append("- None.")

    if agent_run is not None:
        lines.extend(["", "## Agent Investigation Plan"])
        if agent_run.hypotheses:
            for hypothesis in agent_run.hypotheses:
                lines.append(f"- [{hypothesis.status}] {hypothesis.label}: {hypothesis.rationale}")
        else:
            lines.append("- No agent hypotheses recorded.")
        if agent_run.actions:
            for action in agent_run.actions:
                target_label = action.query or action.path
                lines.append(f"  - action={action.kind} target={target_label} reason={action.reason}")

        lines.extend(["", "## Agent Observations"])
        if agent_run.observations:
            for observation in agent_run.observations[:20]:
                lines.append(
                    f"- {observation.path} via {observation.source_mechanism} "
                    f"(confidence={observation.confidence:.2f})"
                )
                if observation.derived_claim:
                    lines.append(f"  Claim: {observation.derived_claim}")
                lines.append(
                    f"  Exit status: {observation.exit_status}  Truncated: {'yes' if observation.truncated else 'no'}"
                )
                helper_hash = observation.metadata.get("helper_source_hash")
                if helper_hash:
                    lines.append(f"  Helper source hash: {helper_hash}")
                lines.append(f"  Evidence: `{observation.evidence}`")
        else:
            lines.append("- No agent observations recorded.")

        rejected = [item for item in agent_run.hypotheses if item.status == "rejected"]
        lines.extend(["", "## Rejected Hypotheses"])
        if rejected:
            for hypothesis in rejected:
                lines.append(f"- {hypothesis.label}: {hypothesis.notes or hypothesis.rationale}")
        else:
            lines.append("- None.")

        lines.extend(["", "## Agent Coverage and Limitations"])
        lines.append(f"- Sandbox available: {'yes' if agent_run.sandbox_available else 'no'}")
        if agent_run.generated_helpers_skipped:
            lines.append("- Generated helpers were skipped.")
        if agent_run.warnings:
            lines.extend(f"- {warning}" for warning in agent_run.warnings)
        else:
            lines.append("- No agent warnings.")

    lines.append("")
    return "\n".join(lines)
