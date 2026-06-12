# doc-triage

`doc-triage` scans a local folder or mounted share for likely secrets, credentials, personal data, and other high-value documents. It writes a single Markdown report and does not keep a database.

The report may contain verbatim secrets. Treat it like sensitive evidence.

## What it does

- Walks a target directory and scores interesting files.
- Uses built-in text matching plus external tools like `rga` and TruffleHog.
- Can OCR images and PDFs when `--ocr` is enabled.
- Can ask a local Ollama model to summarize and prioritize findings.
- Writes reports with mode `0600`.

## Quick start

Install the package:

```bash
python3 -m pip install -e .
```

Check what is missing on the current machine:

```bash
doc-triage doctor
```

Run a deterministic scan without any LLM calls:

```bash
doc-triage scan /path/to/share --output report.md --no-llm
```

Run with OCR and Ollama:

```bash
doc-triage scan /path/to/share --output report.md --ocr --model huihui_ai/qwen3.5-abliterated:9b
```

Run the new agentic mode, which profiles the dataset, chooses context-specific follow-up reads/searches, and adds agent provenance to the report:

```bash
doc-triage --verbose scan /path/to/share \
  --output report.md \
  --model huihui_ai/qwen3.5-abliterated:9b \
  --agent \
  --agent-max-actions 8 \
  --agent-timeout 30
```

Exclude noisy paths:

```bash
doc-triage scan /path/to/share --output report.md --exclude '*.zip' --exclude 'tmp/*'
```

## Dependencies

Required for the full scan path:

- `ripgrep`
- `ripgrep-all`
- `trufflehog`

Optional but useful:

- `tesseract` for image OCR
- `ocrmypdf` and `pdftotext` for scanned PDFs
- `ollama` for local LLM summaries

Base Ubuntu packages:

```bash
sudo apt update
sudo apt install ripgrep tesseract-ocr poppler-utils
```

Recommended extras:

```bash
# ripgrep-all
cargo install ripgrep_all

# TruffleHog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh

# OCR for PDFs
sudo apt install ocrmypdf
```

Ollama setup is covered below.

## Common commands

Check dependencies and versions:

```bash
doc-triage doctor
```

Scan without LLM analysis:

```bash
doc-triage scan /mnt/share --output report.md --no-llm
```

Show stage-by-stage progress during a test run:

```bash
doc-triage --verbose scan /mnt/share --output report.md --no-llm
```

Scan with OCR:

```bash
doc-triage scan /mnt/share --output report.md --ocr --no-llm
```

Scan with OCR and a local model:

```bash
doc-triage scan /mnt/share --output report.md --ocr --model huihui_ai/qwen3.5-abliterated:9b
```

Scan with the agent loop enabled:

```bash
doc-triage --verbose scan /mnt/share --output report.md --agent --model huihui_ai/qwen3.5-abliterated:9b
```

## Report shape

Every report includes:

1. Scope and scan settings
2. Coverage warnings
3. Executive summary
4. Ranked findings
5. Secret and credential findings
6. Personal and financial findings
7. Interesting document relationships
8. Files to review first

When `--agent` is enabled the report also adds:

9. Agent investigation plan
10. Agent observations
11. Rejected hypotheses
12. Agent coverage and limitations

## Ollama setup

Install Ollama:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Start the service:

```bash
systemctl --user enable --now ollama
```

If your install uses a system service instead:

```bash
sudo systemctl enable --now ollama
```

Pull the abliterated default model:

```bash
ollama pull huihui_ai/qwen3.5-abliterated:9b
```

Verify:

```bash
ollama list
doc-triage doctor
```

## Notes

- Missing external scanners produce warnings in the report and a non-zero exit code.
- OCR is opt-in and only writes to a temporary workspace.
- Source files are never modified.
- Use this only on data you are authorized to inspect.
