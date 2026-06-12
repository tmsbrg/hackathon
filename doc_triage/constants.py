from __future__ import annotations

import re


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

REQUIRED_TOOLS = ("rg", "rga", "trufflehog")
OPTIONAL_OCR_TOOLS = ("tesseract", "ocrmypdf", "pdftotext", "exiftool")
ARCHIVE_EXTENSIONS = {".zip", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".rar"}
TEXT_EXTENSIONS = {".txt", ".md", ".cfg", ".conf", ".log", ".ini", ".json", ".yaml", ".yml", ".csv"}
OCR_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp"}
OCR_PDF_EXTENSIONS = {".pdf"}
SENSITIVE_FILENAMES = {
    ".env": ("credential", "high"),
    "id_rsa": ("sensitive-file", "critical"),
    "id_dsa": ("sensitive-file", "critical"),
    "credentials.txt": ("credential", "high"),
    "secrets.txt": ("credential", "high"),
    "config.ovpn": ("sensitive-file", "medium"),
}
KEYWORD_RULES = {
    "password": ("credential", "high", 0.95),
    "iban": ("financial-data", "medium", 0.7),
    "bsn": ("personal-data", "medium", 0.7),
}
SIGNAL_PATTERNS: tuple[tuple[re.Pattern[str], tuple[str, str, float]], ...] = (
    (
        re.compile(r"\b(?:flag|bonus|idek|bi0sCTF|EQCTF|icc)\{[^}\s]{3,120}\}", re.IGNORECASE),
        ("challenge-flag", "high", 0.98),
    ),
    (re.compile(r"\bpassword\b\s*[:=]", re.IGNORECASE), ("credential", "high", 0.95)),
    (re.compile(r"\b[\w-]*wachtwoord\b\s*[:=]", re.IGNORECASE), ("credential", "high", 0.95)),
    (re.compile(r"\b(passwd|pwd)\b\s*[:=]", re.IGNORECASE), ("credential", "high", 0.95)),
    (re.compile(r"\b(secret|client_secret)\b\s*[:=]", re.IGNORECASE), ("credential", "high", 0.9)),
    (re.compile(r"\baws_secret_access_key\b", re.IGNORECASE), ("credential", "high", 0.95)),
    (re.compile(r"\b[\w-]*token\b\s*[:=]", re.IGNORECASE), ("credential", "high", 0.9)),
    (re.compile(r"\bapi[_-]?key(?:[_-]value)?\b\s*[:=]?", re.IGNORECASE), ("credential", "high", 0.9)),
    (re.compile(r"\b[a-z][a-z0-9]{1,24}_api_[A-Za-z0-9_!.-]{6,}\b", re.IGNORECASE), ("credential", "high", 0.9)),
    (re.compile(r"\bbearer\s+[A-Za-z0-9._-]+", re.IGNORECASE), ("credential", "high", 0.9)),
    (re.compile(r"\bset-cookie\b.*\bhttponly\b", re.IGNORECASE), ("credential", "high", 0.9)),
    (re.compile(r"\biban\b", re.IGNORECASE), ("financial-data", "medium", 0.7)),
    (re.compile(r"\bbsn\b", re.IGNORECASE), ("personal-data", "medium", 0.7)),
    (re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"), ("sensitive-file", "critical", 0.99)),
    (re.compile(r"\bopenssh private key\b", re.IGNORECASE), ("sensitive-file", "critical", 0.98)),
)
SIGNAL_PATTERN_LABELS = (
    "pattern:flag-artifact",
    "pattern:password-assignment",
    "pattern:wachtwoord-assignment",
    "pattern:passwd-assignment",
    "pattern:secret-assignment",
    "pattern:aws-secret-access-key",
    "pattern:token-assignment",
    "pattern:api-key",
    "pattern:api-token-value",
    "pattern:bearer-token",
    "pattern:set-cookie-httponly",
    "pattern:iban-keyword",
    "pattern:bsn-keyword",
    "pattern:private-key-block",
    "pattern:openssh-private-key",
)
DOC_NOISE_FILENAMES = {
    "license",
    "license.txt",
    "license.md",
    "readme",
    "readme.txt",
    "readme.md",
    "contributing.md",
    "copying",
    "notice",
    "notice.txt",
}
NOISE_PHRASES = (
    "capture the flag",
    "mit license",
    "copyright",
    "please see individual challenges",
    "can you find",
    "hint:",
)
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
ANSI_RESET = "\033[0m"
ANSI_COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "ok": "\033[32m",
    "warning": "\033[33m",
    "info": "\033[36m",
}
NON_FATAL_WARNING_PREFIXES = (
    "agent planning failed:",
    "agent summary failed:",
    "agent refinement failed:",
    "Ollama response repair failed:",
    "Ollama response did not include the required JSON keys.",
)
