from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ToolStatus:
    name: str
    path: str | None
    required: bool


@dataclass(slots=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    metadata: dict[str, bool] = field(default_factory=dict)


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


@dataclass(slots=True)
class HelperRequest:
    kind: str
    path: str
    reason: str
    limit: int = 20


@dataclass(slots=True)
class AgentHypothesis:
    label: str
    rationale: str
    status: str = "inconclusive"
    evidence_paths: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass(slots=True)
class AgentAction:
    kind: str
    reason: str
    path: str = "."
    query: str = ""
    limit: int = 20
    code: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class AgentObservation:
    path: str
    evidence: str
    source_mechanism: str
    confidence: float
    derived_claim: str = ""
    action_kind: str = ""
    exit_status: int = 0
    truncated: bool = False
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class AgentRun:
    hypotheses: list[AgentHypothesis] = field(default_factory=list)
    actions: list[AgentAction] = field(default_factory=list)
    observations: list[AgentObservation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    llm_summary: dict[str, object] | None = None
    reviewed_findings: list[Finding] = field(default_factory=list)
    removed_findings: list[Finding] = field(default_factory=list)
    sandbox_available: bool = False
    generated_helpers_skipped: bool = False
