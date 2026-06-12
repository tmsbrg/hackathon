import json
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest import mock

from doc_triage import cli


class ContractEdgeTests(unittest.TestCase):
    def test_run_command_caps_stdout_and_marks_truncation(self) -> None:
        result = cli.run_command(["python3", "-c", "print('x' * 5000)"], max_output_chars=100)

        self.assertEqual(result.exit_code, 0)
        self.assertTrue(result.metadata["stdout_truncated"])
        self.assertLessEqual(len(result.stdout), 100)

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    def test_scan_target_respects_exclude_globs(self, _: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            keep = target / "keep.txt"
            skip = target / "skip.txt"
            keep.write_text("password=keep\n", encoding="utf-8")
            skip.write_text("password=skip\n", encoding="utf-8")

            findings, warnings = cli.scan_target(target, max_files=None, exclude_globs=["skip*"])

            self.assertEqual(warnings, [])
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].source, "keep.txt")

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
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
    def test_scan_does_not_scan_output_report_inside_target(self, _: mock.Mock, __: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir, "case")
            target.mkdir()
            (target / "loot.txt").write_text("password=secret\n", encoding="utf-8")
            output = target / "report.md"

            exit_code = cli.main(["scan", str(target), "--output", str(output), "--no-llm"])

            self.assertEqual(exit_code, 0)
            report = output.read_text(encoding="utf-8")
            self.assertIn("loot.txt", report)
            self.assertNotIn("report.md:", report)

    @mock.patch("doc_triage.cli.urlopen")
    def test_llm_summary_repairs_non_json_response_once(self, urlopen: mock.Mock) -> None:
        first = mock.Mock()
        first.__enter__ = mock.Mock(return_value=first)
        first.__exit__ = mock.Mock(return_value=False)
        first.read.return_value = json.dumps({"response": "not json"}).encode("utf-8")

        second = mock.Mock()
        second.__enter__ = mock.Mock(return_value=second)
        second.__exit__ = mock.Mock(return_value=False)
        second.read.return_value = json.dumps(
            {
                "response": json.dumps(
                    {
                        "executive_summary": "fixed",
                        "priority_findings": [],
                        "relationships": [],
                        "review_order": [],
                    }
                )
            }
        ).encode("utf-8")
        urlopen.side_effect = [first, second]

        result = cli.generate_llm_summary(
            "http://127.0.0.1:11434",
            "qwen3:8b",
            [
                cli.Finding(
                    source="a.txt",
                    category="credential",
                    severity="high",
                    detector="rga",
                    evidence="password=secret",
                    line=1,
                    confidence=0.9,
                    metadata={},
                )
            ],
            max_files=30,
        )

        self.assertEqual(result["executive_summary"], "fixed")
        self.assertEqual(urlopen.call_count, 2)

    @mock.patch("doc_triage.cli.urlopen")
    def test_doctor_prints_ollama_health_when_available(self, urlopen: mock.Mock) -> None:
        response = mock.Mock()
        response.__enter__ = mock.Mock(return_value=response)
        response.__exit__ = mock.Mock(return_value=False)
        response.read.return_value = json.dumps({"models": [{"name": "qwen3:8b"}]}).encode("utf-8")
        urlopen.return_value = response

        with mock.patch("doc_triage.cli.tool_version", side_effect=lambda name: f"{name}-1.0"), mock.patch(
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
        ):
            stdout = StringIO()
            with mock.patch("sys.stdout", stdout):
                exit_code = cli.run_doctor()

        self.assertEqual(exit_code, 0)
        self.assertIn("healthy", stdout.getvalue())
        self.assertIn("rg-1.0", stdout.getvalue())

    def test_cleanup_tempdirs_removes_registered_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir, "ocr-work")
            temp_path.mkdir()
            cli.register_tempdir(temp_path)
            self.assertTrue(temp_path.exists())

            cli.cleanup_tempdirs()

            self.assertFalse(temp_path.exists())


if __name__ == "__main__":
    unittest.main()
