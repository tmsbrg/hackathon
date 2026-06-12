import tempfile
import unittest
from pathlib import Path
from unittest import mock

from doc_triage import cli


class OcrTests(unittest.TestCase):
    @mock.patch("doc_triage.cli.run_command")
    def test_collect_ocr_findings_uses_tesseract_for_images(self, run_command: mock.Mock) -> None:
        run_command.side_effect = [
            cli.CommandResult(0, "", "", False),
            cli.CommandResult(0, "", "", False),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            image = target / "scan.png"
            image.write_bytes(b"fake")

            ocr_dir = target / "ocr"
            ocr_dir.mkdir()
            (ocr_dir / "scan.txt").write_text("password=secret\n", encoding="utf-8")

            findings, warnings = cli.collect_ocr_findings(target, [image], ocr_dir)

        self.assertEqual(warnings, [])
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(all(finding.metadata["ocr_source"] == "scan.png" for finding in findings))

    @mock.patch("doc_triage.cli.run_command")
    def test_collect_ocr_findings_warns_when_tool_fails(self, run_command: mock.Mock) -> None:
        run_command.return_value = cli.CommandResult(1, "", "boom", False)

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            image = target / "scan.png"
            image.write_bytes(b"fake")

            findings, warnings = cli.collect_ocr_findings(target, [image], target / "ocr")

        self.assertEqual(findings, [])
        self.assertEqual(len(warnings), 1)


if __name__ == "__main__":
    unittest.main()
