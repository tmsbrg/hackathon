from __future__ import annotations

import os
import shutil
import signal
import stat
import subprocess
from pathlib import Path

from .constants import ANSI_COLORS, ANSI_RESET
from .models import AgentAction, CommandResult


REGISTERED_TEMPDIRS: set[Path] = set()


def verbose_log(enabled: bool, message: str) -> None:
    if enabled:
        print(f"[doc-triage] {message}")


def progress_log(enabled: bool, stage: str, message: str) -> None:
    if enabled:
        print(f"[doc-triage] [{stage}] {message}")


def summarize_agent_action(action: AgentAction) -> str:
    target = action.query or action.path
    return f"{action.kind}({target})"


def truncate_output(value: str, max_output_chars: int) -> tuple[str, bool]:
    if len(value) <= max_output_chars:
        return value, False
    truncated = value[:max_output_chars]
    last_newline = truncated.rfind("\n")
    if last_newline > 0:
        truncated = truncated[: last_newline + 1]
    return truncated, True


def colorize(label: str, color: str) -> str:
    return f"{ANSI_COLORS[color]}{label}{ANSI_RESET}"


def safe_relative_path(target: Path, relative_path: str) -> Path | None:
    candidate = (target / relative_path).resolve()
    try:
        candidate.relative_to(target)
    except ValueError:
        return None
    return candidate


def run_command(
    command: list[str],
    timeout: int = 30,
    cwd: Path | None = None,
    max_output_chars: int = 20000,
) -> CommandResult:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=str(cwd) if cwd is not None else None,
            check=False,
        )
        stdout, stdout_truncated = truncate_output(completed.stdout, max_output_chars)
        stderr, stderr_truncated = truncate_output(completed.stderr, max_output_chars)
        return CommandResult(
            exit_code=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=False,
            metadata={"stdout_truncated": stdout_truncated, "stderr_truncated": stderr_truncated},
        )
    except subprocess.TimeoutExpired as exc:
        stdout, stdout_truncated = truncate_output(exc.stdout or "", max_output_chars)
        stderr, stderr_truncated = truncate_output(exc.stderr or "", max_output_chars)
        return CommandResult(
            exit_code=1,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
            metadata={"stdout_truncated": stdout_truncated, "stderr_truncated": stderr_truncated},
        )
    except FileNotFoundError as exc:
        return CommandResult(
            exit_code=127,
            stdout="",
            stderr=str(exc),
            timed_out=False,
            metadata={"stdout_truncated": False, "stderr_truncated": False},
        )


def tool_version(name: str) -> str:
    commands = {
        "rg": [name, "--version"],
        "rga": [name, "--version"],
        "trufflehog": [name, "--version"],
        "tesseract": [name, "--version"],
        "ocrmypdf": [name, "--version"],
        "pdftotext": [name, "-v"],
        "ollama": [name, "--version"],
    }
    command = commands.get(name)
    if command is None:
        return "unknown"
    result = run_command(command, timeout=5, max_output_chars=200)
    if result.exit_code != 0:
        return "unavailable"
    first_line = (result.stdout or result.stderr).splitlines()
    return first_line[0].strip() if first_line else "unknown"


def register_tempdir(path: Path) -> None:
    REGISTERED_TEMPDIRS.add(path)


def unregister_tempdir(path: Path) -> None:
    REGISTERED_TEMPDIRS.discard(path)


def cleanup_tempdirs() -> None:
    for path in list(REGISTERED_TEMPDIRS):
        shutil.rmtree(path, ignore_errors=True)
        unregister_tempdir(path)


def install_signal_handlers() -> None:
    def _handle_signal(signum: int, _frame: object) -> None:
        cleanup_tempdirs()
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)


def write_report(path: Path, content: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
