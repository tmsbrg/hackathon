import tempfile
import unittest
from pathlib import Path
from unittest import mock

from doc_triage import cli


class OcrTests(unittest.TestCase):
    @mock.patch("doc_triage.cli.run_command")
    def test_collect_ocr_findings_uses_tesseract_for_all_documented_image_extensions(self, run_command: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            ocr_dir = target / "ocr"
            ocr_dir.mkdir()
            images = []
            for suffix in sorted(cli.OCR_IMAGE_EXTENSIONS):
                image = target / f"scan{suffix}"
                image.write_bytes(b"fake")
                images.append(image)
                (ocr_dir / "scan.txt").write_text("password=secret\n", encoding="utf-8")

            run_command.side_effect = [cli.CommandResult(0, "", "", False) for _ in range(len(images))]
            findings, warnings = cli.collect_ocr_findings(target, images, ocr_dir)

        self.assertEqual(warnings, [])
        found_sources = {finding.metadata["ocr_source"] for finding in findings}
        self.assertEqual(found_sources, {f"scan{suffix}" for suffix in cli.OCR_IMAGE_EXTENSIONS})
        for call, image in zip(run_command.call_args_list, images):
            self.assertEqual(call.kwargs["progress_stage"], "ocr")
            self.assertEqual(call.kwargs["progress_message"], f"OCR {image.name}")
            self.assertTrue(call.kwargs["progress_enabled"])

    @mock.patch("doc_triage.cli.shutil.which", side_effect=lambda name: f"/usr/bin/{name}")
    @mock.patch("doc_triage.cli.run_command")
    def test_collect_ocr_findings_uses_pdf_ocr_for_all_documented_pdf_extensions(
        self,
        run_command: mock.Mock,
        _: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            work_dir = target / "ocr"
            work_dir.mkdir()
            pdfs = []
            for suffix in sorted(cli.OCR_PDF_EXTENSIONS):
                sample = target / f"scan{suffix}"
                sample.write_bytes(b"%PDF-1.4")
                pdfs.append(sample)
                output_pdf = work_dir / sample.name
                output_pdf.write_bytes(b"%PDF-1.4")
                (work_dir / f"{sample.stem}.txt").write_text("password=secret\n", encoding="utf-8")

            run_command.side_effect = [cli.CommandResult(0, "", "", False) for _ in range(len(pdfs) * 2)]
            findings, warnings = cli.collect_ocr_findings(target, pdfs, work_dir)

        self.assertEqual(warnings, [])
        found_sources = {finding.metadata["ocr_source"] for finding in findings}
        self.assertEqual(found_sources, {f"scan{suffix}" for suffix in cli.OCR_PDF_EXTENSIONS})
        for call in run_command.call_args_list:
            self.assertEqual(call.kwargs["progress_stage"], "ocr")
            self.assertTrue(call.kwargs["progress_enabled"])

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
