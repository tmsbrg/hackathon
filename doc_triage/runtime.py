from __future__ import annotations

import os
import shutil
import signal
import stat
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .constants import ANSI_COLORS, ANSI_RESET
from .models import AgentAction, CommandResult


REGISTERED_TEMPDIRS: set[Path] = set()
ACTIVE_PROCESSES: set[subprocess.Popen[str]] = set()
ACTIVE_CLOSEABLES: set[Any] = set()


def _timestamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _log_prefix(stage: str | None = None) -> str:
    prefix = f"[{_timestamp()}] [doc-triage]"
    return f"{prefix} [{stage}]" if stage else prefix


def _format_elapsed_seconds(elapsed: float) -> str:
    if elapsed < 1:
        return f"{elapsed:.1f}s"
    if elapsed < 10:
        return f"{elapsed:.1f}s"
    return f"{int(elapsed)}s"


def verbose_log(enabled: bool, message: str) -> None:
    if enabled:
        print(f"{_log_prefix()} {message}")


def progress_log(enabled: bool, stage: str, message: str) -> None:
    print(f"{_log_prefix(stage)} {message}")


class ProgressTicker:
    def __init__(self, enabled: bool, stage: str, message: str, interval_seconds: float = 1.0) -> None:
        self.enabled = enabled
        self.stage = stage
        self.message = message
        self.interval_seconds = interval_seconds
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._start_time = 0.0
        self._line_length = 0

    def __enter__(self) -> "ProgressTicker":
        if not self.enabled:
            return self
        self._start_time = time.monotonic()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.stop()

    def _render(self, suffix: str = "") -> str:
        elapsed = time.monotonic() - self._start_time
        line = f"{_log_prefix(self.stage)} {self.message} ({_format_elapsed_seconds(elapsed)})"
        return f"{line} {suffix}".rstrip()

    def _write(self, content: str) -> None:
        padding = max(0, self._line_length - len(content))
        print("\r" + content + (" " * padding), end="", flush=True)
        self._line_length = len(content)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self._write(self._render())
            if self._stop_event.wait(self.interval_seconds):
                break

    def stop(self, suffix: str = "") -> None:
        if not self.enabled:
            return
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval_seconds + 0.2)
        self._write(self._render(suffix))
        print(flush=True)


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
    progress_stage: str | None = None,
    progress_message: str | None = None,
    progress_enabled: bool = False,
) -> CommandResult:
    process: subprocess.Popen[str] | None = None
    ticker: ProgressTicker | None = None
    try:
        if progress_stage and progress_message:
            ticker = ProgressTicker(progress_enabled, progress_stage, progress_message)
            ticker.__enter__()
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
        if ticker is not None:
            ticker.stop("done")
        return CommandResult(
            exit_code=process.returncode or 0,
            stdout=stdout,
            stderr=stderr,
            timed_out=False,
            metadata={"stdout_truncated": stdout_truncated, "stderr_truncated": stderr_truncated},
        )
    except subprocess.TimeoutExpired as exc:
        if ticker is not None:
            ticker.stop(f"timed out after {timeout}s")
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
        if ticker is not None:
            ticker.stop("failed")
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
        if ticker is not None and not ticker._stop_event.is_set():
            ticker.stop("failed")


def read_with_progress(
    enabled: bool,
    stage: str,
    message: str,
    reader: Callable[[], bytes],
) -> bytes:
    with ProgressTicker(enabled, stage, message) as ticker:
        payload = reader()
        ticker.stop("done")
        return payload


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
