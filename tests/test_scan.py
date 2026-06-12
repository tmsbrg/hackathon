import tempfile
import unittest
from pathlib import Path
from unittest import mock

from doc_triage import cli


class ScanLogicTests(unittest.TestCase):
    def test_bsn_validator_accepts_valid_value(self) -> None:
        self.assertTrue(cli.is_valid_bsn("123456782"))

    def test_bsn_validator_rejects_invalid_value(self) -> None:
        self.assertFalse(cli.is_valid_bsn("123456789"))

    def test_deduplicate_findings_collapses_same_source_category_and_evidence(self) -> None:
        findings = [
            cli.Finding(
                source="a.txt",
                category="credential",
                severity="high",
                detector="rga",
                evidence="password=secret",
                line=1,
                confidence=0.9,
                metadata={},
            ),
            cli.Finding(
                source="a.txt",
                category="credential",
                severity="medium",
                detector="built-in",
                evidence="password=secret",
                line=8,
                confidence=0.2,
                metadata={},
            ),
        ]

        deduped = cli.deduplicate_findings(findings)

        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0].severity, "high")
        self.assertEqual(deduped[0].detector, "rga")

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    def test_scan_target_marks_sensitive_filenames_even_without_text_hits(self, _: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            secret_file = target / "id_rsa"
            secret_file.write_text("placeholder\n", encoding="utf-8")

            findings, warnings = cli.scan_target(target, max_files=None)

            self.assertEqual(warnings, [])
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].category, "sensitive-file")

    def test_render_report_contains_expected_sections(self) -> None:
        args = cli.build_parser().parse_args(["scan", "/tmp/example", "--no-llm"])
        finding = cli.Finding(
            source="Finance/notes.txt",
            category="credential",
            severity="high",
            detector="rga",
            evidence="password=secret",
            line=4,
            confidence=0.95,
            metadata={},
        )

        report = cli.render_report(args, Path("/tmp/example"), [finding], [])

        self.assertIn("## Scope", report)
        self.assertIn("## Ranked High-Value Findings", report)
        self.assertIn("Finance/notes.txt", report)
        self.assertIn("password=secret", report)


if __name__ == "__main__":
    unittest.main()
