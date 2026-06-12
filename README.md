# doc-triage

`doc-triage` scans an authorized local directory or mounted share for likely high-value documents, credentials, secrets, and personal or financial data. It writes a single Markdown report and keeps findings in memory.

The report may include verbatim secrets. Treat it like sensitive material.

## Features

- `doctor` checks required scanners, optional OCR tools, and local LLM availability.
- `scan` combines filename heuristics, built-in text matching, `ripgrep-all`, TruffleHog, optional OCR, and optional Ollama summarization.
- Reports are written with mode `0600`.

## Install

Python:

```bash
python3 -m pip install -e .
```

Ubuntu toolchain:

```bash
sudo apt update
sudo apt install ripgrep tesseract-ocr poppler-utils
```

Recommended extra tools:

```bash
# ripgrep-all
cargo install ripgrep_all

# TruffleHog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh

# Ollama
curl -fsSL https://ollama.com/install.sh | sh

# OCR for PDFs
sudo apt install ocrmypdf
```

## Usage

Check dependencies:

```bash
doc-triage doctor
```

Scan a folder without LLM analysis:

```bash
doc-triage scan /mnt/share --output report.md --no-llm
```

Scan with OCR and Ollama:

```bash
doc-triage scan /mnt/share --output report.md --ocr --model qwen3:8b
```

## Notes

- Missing external scanners produce warnings in the report and a non-zero exit code.
- OCR is opt-in and only writes to a temporary workspace.
- Source files are never modified.
- Use this only on data you are authorized to inspect.
