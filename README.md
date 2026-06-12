# doc-triage

`doc-triage` is a dependency-light local triage CLI for scanning an authorized directory or mounted share for high-value findings. It combines deterministic scanners (`rg`, `rga`, TruffleHog, optional OCR) with an optional local Ollama-backed agent loop, then writes one self-contained Markdown report.

The report may contain verbatim secrets. Treat it like sensitive evidence.

## Current scope

- Linux only
- Python 3.10+
- Local files or already-mounted shares
- Local-only Ollama usage
- No database, web UI, or persistent extraction cache

## Features

- Deterministic scanning for credentials, flags, personal data, and sensitive filenames
- Optional OCR for images and PDFs
- Optional agent mode that profiles the dataset, proposes read-only follow-up actions, executes them, and summarizes results
- Restrictive report permissions (`0600`)
- Verbose terminal progress, including raw planner/refinement output in `--verbose` mode

## Install

Install the package in editable mode:

```bash
python3 -m pip install -e .
```

There are no required Python runtime dependencies beyond the standard library. External scanners are invoked as subprocesses.

## CLI

Top-level commands:

```text
doc-triage doctor
doc-triage scan TARGET
  [--output PATH]
  [--model NAME]
  [--ollama-url URL]
  [--ocr]
  [--max-files N]
  [--max-llm-files N]
  [--exclude GLOB]
  [--no-llm]
  [--agent]
  [--multi-agent]
  [--agent-max-actions N]
  [--agent-timeout SECONDS]
  [--model-retries N]
  [--verbose]
```

Useful defaults:

- `--output ./report.md`
- `--model huihui_ai/qwen3.5-abliterated:9b`
- `--ollama-url http://127.0.0.1:11434`
- `--max-llm-files 30`
- `--agent-max-actions 8`
- `--agent-timeout 30`
- `--model-retries 1`

## Quick start

Check the current machine first:

```bash
doc-triage doctor
```

Run a deterministic scan:

```bash
doc-triage scan /path/to/share --output report.md
```

Run with OCR:

```bash
doc-triage scan /path/to/share --output report.md --ocr
```

Run the single-agent plan/do/check/act loop:

```bash
doc-triage scan /path/to/share --output report.md --agent --model huihui_ai/qwen3.5-abliterated:9b
```

Run the multi-agent subagent flow with verbose planning output:

```bash
doc-triage --verbose scan /path/to/share \
  --output report.md \
  --model haervwe/GLM-4.6V-Flash-9B \
  --multi-agent \
  --agent-max-actions 8 \
  --agent-timeout 30
```

Exclude noisy paths:

```bash
doc-triage scan /path/to/share --output report.md --exclude '*.zip' --exclude 'tmp/*'
```

## External tools

Required for the full deterministic scanner path:

- `rg`
- `rga`
- `trufflehog`

Optional:

- `tesseract` for image OCR
- `ocrmypdf` and `pdftotext` for scanned PDFs
- `exiftool` for metadata extraction in agent mode
- `ollama` for local summaries and agent planning
- `bwrap` for sandboxed generated helpers

### Ubuntu notes

Base packages:

```bash
sudo apt update
sudo apt install ripgrep tesseract-ocr poppler-utils exiftool
```

Recommended extras:

```bash
# ripgrep-all
cargo install ripgrep_all

# TruffleHog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh

# OCR for PDFs
sudo apt install ocrmypdf

# Bubblewrap sandbox
sudo apt install bubblewrap
```

## Supported document types

The list below is intentionally limited to what the current code path demonstrably handles today.

### Direct deterministic content scanning

These file types are read directly by the built-in Python scanner when they are plain local files:

- `.txt`
- `.md`
- `.cfg`
- `.conf`
- `.log`
- `.ini`
- `.json`
- `.yaml`
- `.yml`
- `.csv`

Sensitive filename rules also apply to specific names regardless of extension, including:

- `.env`
- `id_rsa`
- `id_dsa`
- `credentials.txt`
- `secrets.txt`
- `config.ovpn`

### OCR-backed scanning

When `--ocr` is enabled:

- image OCR is supported for:
  - `.png`
  - `.jpg`
  - `.jpeg`
  - `.tif`
  - `.tiff`
  - `.bmp`
- PDF OCR / text extraction is supported for:
  - `.pdf`

### Agent/helper-supported artifact types

The agent loop and helper actions can currently inspect or triage:

- email artifacts:
  - `.eml`
- archive/container types:
  - `.zip`
  - `.7z`
  - `.tar`
  - `.gz`
  - `.tgz`
  - `.bz2`
  - `.xz`
  - `.rar`
- images via OCR / metadata:
  - `.png`
  - `.jpg`
  - `.jpeg`
  - `.tif`
  - `.tiff`
  - `.bmp`
- PDFs via `pdftotext`
  - `.pdf`

In addition, the agent reconnaissance path samples these text-like types when building context:

- `.xml`
- `.html`
- `.tsv`

### Generic file-level inspection

Even when no type-specific extractor applies, the current agent path can still do bounded inspection through:

- directory listing
- filename/path search
- regex content search via `rga`
- `file(1)` type inspection
- `strings` on binary-like files

### Not a promise of full parsing support

Current support does **not** mean first-class parsing for every office, mail, archive, or forensic artifact format. For example:

- `.docx`, `.xlsx`, `.pptx`, SQLite, and PCAP are not yet handled by dedicated built-in parsers
- those files may still be partially surfaced by `rga`, filenames, `file`, `strings`, or model-chosen helper actions
- if a parser is missing or the model chooses an incompatible action, `doc-triage` records a warning and continues

## Ollama setup

Install Ollama:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Start the service:

```bash
systemctl --user enable --now ollama
```

If your setup uses a system service instead:

```bash
sudo systemctl enable --now ollama
```

Pull a local model:

```bash
ollama pull haervwe/GLM-4.6V-Flash-9B
```

Verify:

```bash
ollama list
doc-triage doctor
```

## What the report contains

Every report includes:

1. Scope and scan settings
2. Coverage and warnings
3. Executive summary
4. Ranked findings
5. Secret and credential findings
6. Personal and financial findings
7. Interesting documents and relationships
8. Files to review first

When `--multi-agent` is enabled, the report also adds:

9. Agent investigation plan
10. Agent observations
11. Rejected hypotheses
12. Agent coverage and limitations

## Terminal output

Normal mode prints a concise colorized summary.

`--verbose` additionally prints:

- scan stage progress
- raw agent planner output
- raw agent refinement output
- LLM/agent warnings as they happen

Deterministic findings use specific detector labels where possible, for example:

- `pattern:flag-artifact`
- `pattern:password-assignment`
- `pattern:set-cookie-httponly`
- `bsn-validator`
- `filename-rule`
- `rga`
- `trufflehog`

## Safety notes

- Use this only on data you are authorized to inspect.
- Source files are never modified.
- OCR and helper execution use temporary workspaces only.
- Missing scanners or partial failures still produce a report, but the command may exit non-zero.
