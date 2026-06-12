from __future__ import annotations

import os
import shutil
import signal
import stat
import subprocess
from pathlib import Path
from typing import Any

from .constants import ANSI_COLORS, ANSI_RESET
from .models import AgentAction, CommandResult


REGISTERED_TEMPDIRS: set[Path] = set()
ACTIVE_PROCESSES: set[subprocess.Popen[str]] = set()
ACTIVE_CLOSEABLES: set[Any] = set()


def verbose_log(enabled: bool, message: str) -> None:
    if enabled:
        print(f"[doc-triage] {message}")


def progress_log(enabled: bool, stage: str, message: str) -> None:
    print(f"[doc-triage] [{stage}] {message}")


def summarize_agent_action(action: AgentAction) -> str:
    target = action.query or action.path
    if action.hypothesis_label:
        return f"{action.kind}({target})[{action.hypothesis_label}]"
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
    target_root = target.resolve()
    candidate = (target_root / relative_path).resolve()
    try:
        candidate.relative_to(target_root)
    except ValueError:
        return None
    return candidate


def register_active_process(process: subprocess.Popen[str]) -> None:
    ACTIVE_PROCESSES.add(process)


def unregister_active_process(process: subprocess.Popen[str]) -> None:
    ACTIVE_PROCESSES.discard(process)


def register_closeable(resource: Any) -> None:
    ACTIVE_CLOSEABLES.add(resource)


def unregister_closeable(resource: Any) -> None:
    ACTIVE_CLOSEABLES.discard(resource)


def abort_active_work() -> None:
    for resource in list(ACTIVE_CLOSEABLES):
        try:
            resource.close()
        except OSError:
            pass
        finally:
            unregister_closeable(resource)

    for process in list(ACTIVE_PROCESSES):
        try:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        finally:
            unregister_active_process(process)


def run_command(
    command: list[str],
    timeout: int = 30,
    cwd: Path | None = None,
    max_output_chars: int = 20000,
) -> CommandResult:
    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(cwd) if cwd is not None else None,
            preexec_fn=os.setsid,
        )
        register_active_process(process)
        stdout_raw, stderr_raw = process.communicate(timeout=timeout)
        stdout, stdout_truncated = truncate_output(stdout_raw, max_output_chars)
        stderr, stderr_truncated = truncate_output(stderr_raw, max_output_chars)
        return CommandResult(
            exit_code=process.returncode or 0,
            stdout=stdout,
            stderr=stderr,
            timed_out=False,
            metadata={"stdout_truncated": stdout_truncated, "stderr_truncated": stderr_truncated},
        )
    except subprocess.TimeoutExpired as exc:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout_raw, stderr_raw = process.communicate()
        else:
            stdout_raw, stderr_raw = exc.stdout or "", exc.stderr or ""
        stdout, stdout_truncated = truncate_output(stdout_raw, max_output_chars)
        stderr, stderr_truncated = truncate_output(stderr_raw, max_output_chars)
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
    finally:
        if process is not None:
            unregister_active_process(process)


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


def handle_interrupt(signum: int) -> None:
    abort_active_work()
    cleanup_tempdirs()
    raise SystemExit(128 + signum)


def install_signal_handlers() -> None:
    def _handle_signal(signum: int, _frame: object) -> None:
        handle_interrupt(signum)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)


def write_report(path: Path, content: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
