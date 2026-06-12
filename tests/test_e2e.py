import tempfile
import unittest
from pathlib import Path
from unittest import mock

from doc_triage import cli


class EndToEndTests(unittest.TestCase):
    @mock.patch(
        "doc_triage.cli.detect_tools",
        return_value=[
            cli.ToolStatus("rg", "/usr/bin/rg", True),
            cli.ToolStatus("rga", "/usr/bin/rga", True),
            cli.ToolStatus("trufflehog", "/usr/bin/trufflehog", True),
            cli.ToolStatus("tesseract", "/usr/bin/tesseract", False),
            cli.ToolStatus("ocrmypdf", "/usr/bin/ocrmypdf", False),
            cli.ToolStatus("pdftotext", "/usr/bin/pdftotext", False),
            cli.ToolStatus("ollama", "/usr/bin/ollama", False),
        ],
    )
    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    def test_scan_builds_report_for_synthetic_corpus(self, _: mock.Mock, __: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir, "case")
            target.mkdir()
            (target / "id_rsa").write_text("placeholder\n", encoding="utf-8")
            (target / "payroll.txt").write_text("employee bsn 123456782\n", encoding="utf-8")
            output = Path(tmpdir, "report.md")

            exit_code = cli.main(["scan", str(target), "--output", str(output), "--no-llm"])

            self.assertEqual(exit_code, 0)
            report = output.read_text(encoding="utf-8")
            self.assertIn("id_rsa", report)
            self.assertIn("123456782", report)
            self.assertIn("Files Recommended for Manual Review", report)


if __name__ == "__main__":
    unittest.main()
