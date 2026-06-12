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

    def test_extract_digit_runs_only_returns_standalone_nine_digit_values(self) -> None:
        values = cli.extract_digit_runs("cookie=abc856516016def bsn 123456782 hash4a616f9437")

        self.assertEqual(values, ["123456782"])

    def test_keyword_findings_suppresses_invalid_bsn_testing_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            path = target / "records.json"
            path.write_text('{"note":"SANDBOX - invalid BSN for testing","bsn":"999999999"}\n', encoding="utf-8")

            findings = cli.keyword_findings(target, path, path.read_text(encoding="utf-8"))

        self.assertEqual(findings, [])

    def test_classify_match_detects_http_only_cookie(self) -> None:
        classification = cli.classify_match(
            '"set-cookie" : "__cfduid=abc; expires=Mon, 27-Jun-16 15:56:37 GMT; path=/; domain=.example.com; HttpOnly",'
        )

        self.assertEqual(classification, ("credential", "high", 0.9))

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

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    def test_scan_target_does_not_flag_generic_secret_titles(self, _: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            readme = target / "README.md"
            readme.write_text("Trinity Of Secrets\n", encoding="utf-8")

            findings, warnings = cli.scan_target(target, max_files=None)

            self.assertEqual(warnings, [])
            self.assertEqual(findings, [])

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    def test_scan_target_supports_all_documented_text_extensions(self, _: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            expected_sources = set()
            for suffix in sorted(cli.TEXT_EXTENSIONS):
                sample = target / f"sample{suffix}"
                sample.write_text("password=secret\n", encoding="utf-8")
                expected_sources.add(f"sample{suffix}")

            findings, warnings = cli.scan_target(target, max_files=None)

        self.assertEqual(warnings, [])
        found_sources = {finding.source for finding in findings}
        self.assertTrue(expected_sources.issubset(found_sources))

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    def test_scan_target_supports_all_documented_sensitive_filenames(self, _: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            for name in sorted(cli.SENSITIVE_FILENAMES):
                (target / name).write_text("placeholder\n", encoding="utf-8")

            findings, warnings = cli.scan_target(target, max_files=None)

        self.assertEqual(warnings, [])
        found_sources = {finding.source for finding in findings}
        self.assertTrue(set(cli.SENSITIVE_FILENAMES).issubset(found_sources))

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
