import os
import stat
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest import mock

from doc_triage import cli


class CliContractTests(unittest.TestCase):
    def test_main_without_args_returns_invalid_usage(self) -> None:
        exit_code = cli.main([])
        self.assertEqual(exit_code, 2)

    def test_doctor_reports_missing_required_dependencies(self) -> None:
        stdout = StringIO()
        with mock.patch("sys.stdout", stdout):
            exit_code = cli.main(["doctor"])
        self.assertIn(exit_code, {0, 1})
        self.assertIn("Required", stdout.getvalue())

    def test_scan_writes_report_with_restrictive_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir, "target")
            target.mkdir()
            Path(target, "note.txt").write_text("password=secret123\n", encoding="utf-8")
            output = Path(tmpdir, "report.md")

            exit_code = cli.main(["scan", str(target), "--output", str(output), "--no-llm"])

            self.assertIn(exit_code, {0, 1})
            self.assertTrue(output.exists())
            mode = stat.S_IMODE(output.stat().st_mode)
            self.assertEqual(mode, 0o600)

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    def test_scan_verbose_prints_progress_messages(self, _: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir, "target")
            target.mkdir()
            Path(target, "note.txt").write_text("password=secret123\n", encoding="utf-8")
            output = Path(tmpdir, "report.md")
            stdout = StringIO()

            with mock.patch("sys.stdout", stdout):
                cli.main(["--verbose", "scan", str(target), "--output", str(output), "--no-llm"])

            self.assertIn("[doc-triage] Starting scan", stdout.getvalue())
            self.assertIn("[doc-triage] Report written successfully", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
