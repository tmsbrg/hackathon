import os
import stat
import tempfile
import unittest
from pathlib import Path

from doc_triage import cli


class CliContractTests(unittest.TestCase):
    def test_main_without_args_returns_invalid_usage(self) -> None:
        exit_code = cli.main([])
        self.assertEqual(exit_code, 2)

    def test_doctor_reports_missing_required_dependencies(self) -> None:
        exit_code = cli.main(["doctor"])
        self.assertIn(exit_code, {0, 1})

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


if __name__ == "__main__":
    unittest.main()
