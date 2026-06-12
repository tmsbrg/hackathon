from __future__ import annotations

import json
import shutil
from urllib.error import URLError
from urllib.request import Request, urlopen

from .constants import EXIT_ERROR, EXIT_OK, OPTIONAL_OCR_TOOLS, REQUIRED_TOOLS
from .models import ToolStatus
from .runtime import tool_version


def ollama_health(ollama_url: str = "http://127.0.0.1:11434") -> tuple[bool, str]:
    request = Request(f"{ollama_url.rstrip('/')}/api/tags", method="GET")
    try:
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        return False, f"unreachable ({exc})"
    models = payload.get("models", [])
    if not isinstance(models, list):
        return False, "invalid response"
    names = [item.get("name", "<unknown>") for item in models if isinstance(item, dict)]
    if not names:
        return True, "healthy (no local models)"
    return True, f"healthy ({', '.join(names)})"


def detect_tools() -> list[ToolStatus]:
    statuses: list[ToolStatus] = []
    for name in REQUIRED_TOOLS:
        statuses.append(ToolStatus(name=name, path=shutil.which(name), required=True))
    for name in OPTIONAL_OCR_TOOLS:
        statuses.append(ToolStatus(name=name, path=shutil.which(name), required=False))
    ollama_path = shutil.which("ollama")
    healthy, _detail = ollama_health()
    if ollama_path is None and healthy:
        ollama_path = "<api-only>"
    statuses.append(ToolStatus(name="ollama", path=ollama_path, required=False))
    return statuses


def run_doctor() -> int:
    statuses = detect_tools()
    missing_required = [tool.name for tool in statuses if tool.required and not tool.path]
    print("Required")
    for tool in [item for item in statuses if item.required]:
        state = tool.path or "missing"
        version = tool_version(tool.name) if tool.path else "n/a"
        print(f"- {tool.name}: {state} [{version}]")
    print("Optional OCR")
    for tool in [item for item in statuses if not item.required and item.name != "ollama"]:
        state = tool.path or "missing"
        version = tool_version(tool.name) if tool.path else "n/a"
        print(f"- {tool.name}: {state} [{version}]")
    print("LLM")
    ollama_status = next(item for item in statuses if item.name == "ollama")
    if ollama_status.path:
        healthy, detail = ollama_health()
        print(f"- ollama: {ollama_status.path} [{detail}]")
    else:
        print("- ollama: missing")
    return EXIT_ERROR if missing_required else EXIT_OK
