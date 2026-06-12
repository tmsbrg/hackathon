import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import tarfile
import gzip
import bz2
import lzma
import zipfile

from doc_triage import cli


class IntegrationTests(unittest.TestCase):
    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    def test_scan_target_extracts_findings_from_docx_and_xlsx(self, _: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            docx_path = target / "vpn.docx"
            with zipfile.ZipFile(docx_path, "w") as archive:
                archive.writestr("word/document.xml", "<w:t>password=VeloCity-VPN-9kLm2!</w:t>")
            xlsx_path = target / "payroll.xlsx"
            with zipfile.ZipFile(xlsx_path, "w") as archive:
                archive.writestr("xl/worksheets/sheet2.xml", "<v>fin_api_NwQ3_8842secret</v>")

            findings, warnings = cli.scan_target(target, max_files=None)

        self.assertEqual(warnings, [])
        sources = {finding.source for finding in findings}
        self.assertIn("vpn.docx::word/document.xml", sources)
        self.assertIn("payroll.xlsx::xl/worksheets/sheet2.xml", sources)

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    def test_scan_target_extracts_findings_from_eml(self, _: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            mail = target / "reset.eml"
            mail.write_text(
                "From: helpdesk@example.com\n"
                "To: user@example.com\n"
                "Subject: reset\n"
                "\n"
                "Tijdelijk_wachtwoord: PortalReset-2024-xK9\n",
                encoding="utf-8",
            )

            findings, warnings = cli.scan_target(target, max_files=None)

        self.assertEqual(warnings, [])
        self.assertTrue(any("PortalReset-2024-xK9" in finding.evidence for finding in findings))

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    def test_scan_target_extracts_findings_from_zip_and_nested_7z(self, _: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            archive_path = target / "backup.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("restore_notes.txt", "password=PgProd_Nordwind_7xK!mQ\n")
                archive.writestr("configs.7z", b"placeholder")

            def run_command_side_effect(command: list[str], **_: object) -> cli.CommandResult:
                if command[0] == "/usr/bin/7z":
                    output_arg = next(arg for arg in command if arg.startswith("-o"))
                    extract_root = Path(output_arg[2:])
                    (extract_root / "oracle_legacy.txt").write_text("password=OrclNw2019!sys\n", encoding="utf-8")
                    return cli.CommandResult(exit_code=0, stdout="", stderr="", timed_out=False)
                raise AssertionError(f"Unexpected command: {command}")

            with mock.patch("doc_triage.cli.shutil.which", side_effect=lambda name: "/usr/bin/7z" if name == "7z" else None):
                with mock.patch("doc_triage.cli.run_command", side_effect=run_command_side_effect):
                    findings, warnings = cli.scan_target(target, max_files=None)

        self.assertEqual(warnings, [])
        sources = {finding.source for finding in findings}
        self.assertIn("backup.zip::restore_notes.txt", sources)
        self.assertIn("backup.zip::configs.7z::oracle_legacy.txt", sources)

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    @mock.patch("doc_triage.cli.collect_pdf_text", return_value=("FLAG{smb_ripgrep_trufflehog_master}\n", None))
    def test_scan_target_extracts_findings_from_pdf_text(self, _: mock.Mock, __: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            pdf = target / "board_minutes.pdf"
            pdf.write_bytes(b"%PDF-1.4\n")

            findings, warnings = cli.scan_target(target, max_files=None)

        self.assertEqual(warnings, [])
        self.assertTrue(any(finding.category == "challenge-flag" for finding in findings))

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    @mock.patch("doc_triage.cli.run_command")
    @mock.patch("doc_triage.cli.shutil.which")
    def test_scan_target_ocr_falls_back_to_pdftoppm_and_tesseract_when_ocrmypdf_missing(
        self,
        which: mock.Mock,
        run_command: mock.Mock,
        _: mock.Mock,
    ) -> None:
        def which_side_effect(name: str) -> str | None:
            mapping = {
                "ocrmypdf": None,
                "pdftoppm": "/usr/bin/pdftoppm",
                "tesseract": "/usr/bin/tesseract",
            }
            return mapping.get(name)

        def run_command_side_effect(command: list[str], **_: object) -> cli.CommandResult:
            if command[0] == "/usr/bin/pdftoppm":
                prefix = Path(command[-1])
                (prefix.parent / f"{prefix.name}-1.png").write_bytes(b"\x89PNG\r\n\x1a\n")
                return cli.CommandResult(exit_code=0, stdout="", stderr="", timed_out=False)
            if command[0] == "/usr/bin/tesseract":
                return cli.CommandResult(exit_code=0, stdout="BSN (burgerservicenummer): 147258364\n", stderr="", timed_out=False)
            raise AssertionError(f"Unexpected command: {command}")

        which.side_effect = which_side_effect
        run_command.side_effect = run_command_side_effect

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            pdf = target / "scan.pdf"
            pdf.write_bytes(b"%PDF-1.4\n")

            findings, warnings = cli.scan_target(target, max_files=None, ocr=True)

        self.assertEqual(warnings, [])
        self.assertTrue(any(finding.metadata.get("ocr_source") == "scan.pdf" for finding in findings))

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    @mock.patch("doc_triage.cli.collect_exif_text", return_value=("User Comment : BONUS{exif_metadata_dig}", None))
    def test_scan_target_extracts_findings_from_image_metadata(self, _: mock.Mock, __: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            photo = target / "office_party.jpg"
            photo.write_bytes(b"\xff\xd8\xff")

            findings, warnings = cli.scan_target(target, max_files=None)

        self.assertEqual(warnings, [])
        self.assertTrue(any("BONUS{exif_metadata_dig}" in finding.evidence for finding in findings))

    def test_list_archive_contents_supports_stdlib_archive_extensions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)

            zip_path = root / "sample.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("inner.txt", "secret\n")

            tar_path = root / "sample.tar"
            member = root / "inner.txt"
            member.write_text("secret\n", encoding="utf-8")
            with tarfile.open(tar_path, "w") as archive:
                archive.add(member, arcname="inner.txt")

            tgz_path = root / "sample.tgz"
            with tarfile.open(tgz_path, "w:gz") as archive:
                archive.add(member, arcname="inner.txt")

            gz_path = root / "single.txt.gz"
            with gzip.open(gz_path, "wb") as handle:
                handle.write(b"secret\n")

            bz2_path = root / "single.txt.bz2"
            with bz2.open(bz2_path, "wb") as handle:
                handle.write(b"secret\n")

            xz_path = root / "single.txt.xz"
            with lzma.open(xz_path, "wb") as handle:
                handle.write(b"secret\n")

            for archive_path, expected in (
                (zip_path, "inner.txt"),
                (tar_path, "inner.txt"),
                (tgz_path, "inner.txt"),
                (gz_path, "single.txt"),
                (bz2_path, "single.txt"),
                (xz_path, "single.txt"),
            ):
                with self.subTest(path=archive_path.name):
                    result = cli.list_archive_contents(archive_path)
                    self.assertEqual(result.exit_code, 0)
                    self.assertIn(expected, result.stdout)

    @mock.patch("doc_triage.cli.run_command")
    @mock.patch("doc_triage.cli.shutil.which")
    def test_list_archive_contents_uses_external_tools_for_7z_and_rar(self, which: mock.Mock, run_command: mock.Mock) -> None:
        def which_side_effect(name: str) -> str | None:
            if name == "7z":
                return "/usr/bin/7z"
            return None

        which.side_effect = which_side_effect
        run_command.return_value = cli.CommandResult(exit_code=0, stdout="file1\nfile2\n", stderr="", timed_out=False)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            for suffix in (".7z", ".rar"):
                archive_path = root / f"sample{suffix}"
                archive_path.write_bytes(b"fake")
                result = cli.list_archive_contents(archive_path)
                self.assertEqual(result.exit_code, 0)
                self.assertEqual(result.stdout, "file1\nfile2\n")

        self.assertTrue(all(call.args[0][0] == "7z" for call in run_command.call_args_list))

    def test_parse_rga_json_produces_findings(self) -> None:
        payload = "\n".join(
            [
                json.dumps(
                    {
                        "type": "match",
                        "data": {
                            "path": {"text": "/tmp/case/notes.txt"},
                            "line_number": 2,
                            "lines": {"text": "password=secret"},
                            "submatches": [{"match": {"text": "password"}}],
                        },
                    }
                ),
            ]
        )

        findings, warnings = cli.parse_rga_output(payload, Path("/tmp/case"))

        self.assertEqual(warnings, [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector, "rga")
        self.assertEqual(findings[0].source, "notes.txt")

    def test_parse_rga_json_skips_license_and_url_noise(self) -> None:
        payload = "\n".join(
            [
                json.dumps(
                    {
                        "type": "match",
                        "data": {
                            "path": {"text": "/tmp/case/LICENSE.txt"},
                            "line_number": 1,
                            "lines": {"text": "MIT License"},
                            "submatches": [{"match": {"text": "License"}}],
                        },
                    }
                ),
                json.dumps(
                    {
                        "type": "match",
                        "data": {
                            "path": {"text": "/tmp/case/link.txt"},
                            "line_number": 2,
                            "lines": {"text": "https://drive.google.com/file/d/abc/view"},
                            "submatches": [{"match": {"text": "https"}}],
                        },
                    }
                ),
            ]
        )

        findings, warnings = cli.parse_rga_output(payload, Path("/tmp/case"))

        self.assertEqual(warnings, [])
        self.assertEqual(findings, [])

    def test_keyword_findings_detects_flag_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            path = target / "note.txt"
            path.write_text("Recovered marker: flag{language}\n", encoding="utf-8")

            findings = cli.keyword_findings(target, path, path.read_text(encoding="utf-8"))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "challenge-flag")
        self.assertEqual(findings[0].detector, "pattern:flag-artifact")
        self.assertIn("flag{language}", findings[0].evidence)

    def test_parse_trufflehog_output_tolerates_invalid_json(self) -> None:
        payload = '{"SourceMetadata":{"Data":{"Filesystem":{"file":"a.txt"}}},"DetectorName":"AWS","Raw":"AKIA..."}\nnope\n'

        findings, warnings = cli.parse_trufflehog_output(payload, Path("/tmp/case"))

        self.assertEqual(len(findings), 1)
        self.assertEqual(len(warnings), 1)
        self.assertEqual(findings[0].detector, "trufflehog")

    @mock.patch("doc_triage.cli.run_command")
    def test_scan_target_uses_external_scanners_when_available(self, run_command: mock.Mock) -> None:
        run_command.side_effect = [
            cli.CommandResult(
                exit_code=0,
                stdout="docs/secret.txt\n",
                stderr="",
                timed_out=False,
            ),
            cli.CommandResult(
                exit_code=0,
                stdout=json.dumps(
                    {
                        "type": "match",
                        "data": {
                            "path": {"text": "/tmp/case/docs/secret.txt"},
                            "line_number": 1,
                            "lines": {"text": "token=abc"},
                            "submatches": [{"match": {"text": "token"}}],
                        },
                    }
                )
                + "\n",
                stderr="",
                timed_out=False,
            ),
            cli.CommandResult(
                exit_code=0,
                stdout=json.dumps(
                    {
                        "SourceMetadata": {"Data": {"Filesystem": {"file": "/tmp/case/docs/secret.txt"}}},
                        "DetectorName": "GitHub",
                        "Raw": "ghp_secret",
                        "Verified": False,
                    }
                )
                + "\n",
                stderr="",
                timed_out=False,
            ),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir, "case")
            docs = target / "docs"
            docs.mkdir(parents=True)
            (docs / "secret.txt").write_text("token=abc\n", encoding="utf-8")

            findings, warnings = cli.scan_target(target, max_files=None)

        self.assertEqual(warnings, [])
        self.assertGreaterEqual(len(findings), 2)
        self.assertEqual(run_command.call_count, 3)

    @mock.patch("doc_triage.cli.run_command")
    def test_run_external_scanners_passes_trufflehog_excludes_via_temp_file(self, run_command: mock.Mock) -> None:
        captured_path: Path | None = None

        def side_effect(command: list[str], **_: object) -> cli.CommandResult:
            nonlocal captured_path
            if command[0] == "rg":
                return cli.CommandResult(exit_code=0, stdout="", stderr="", timed_out=False)
            if command[0] == "rga":
                return cli.CommandResult(exit_code=1, stdout="", stderr="", timed_out=False)
            if command[0] == "trufflehog":
                self.assertEqual(command.count("--exclude-paths"), 1)
                captured_path = Path(command[command.index("--exclude-paths") + 1])
                self.assertTrue(captured_path.exists())
                self.assertEqual(
                    captured_path.read_text(encoding="utf-8"),
                    ".*/ANSWER\\.txt\n.*/HINT\\.txt\n",
                )
                return cli.CommandResult(exit_code=0, stdout="", stderr="", timed_out=False)
            raise AssertionError(f"Unexpected command: {command}")

        run_command.side_effect = side_effect

        findings, warnings = cli.run_external_scanners(
            Path("/tmp/case"),
            exclude_globs=["*/ANSWER.txt", "*/HINT.txt"],
        )

        self.assertEqual(findings, [])
        self.assertEqual(warnings, [])
        self.assertIsNotNone(captured_path)
        self.assertFalse(captured_path.exists())

    @mock.patch("doc_triage.cli.run_command")
    def test_run_external_scanners_expands_rga_globs_for_recursive_excludes(self, run_command: mock.Mock) -> None:
        seen_rga_command: list[str] | None = None

        def side_effect(command: list[str], **_: object) -> cli.CommandResult:
            nonlocal seen_rga_command
            if command[0] == "rg":
                return cli.CommandResult(exit_code=0, stdout="", stderr="", timed_out=False)
            if command[0] == "rga":
                seen_rga_command = command
                return cli.CommandResult(exit_code=1, stdout="", stderr="", timed_out=False)
            if command[0] == "trufflehog":
                return cli.CommandResult(exit_code=0, stdout="", stderr="", timed_out=False)
            raise AssertionError(f"Unexpected command: {command}")

        run_command.side_effect = side_effect

        cli.run_external_scanners(Path("/tmp/case"), exclude_globs=["*/ANSWER.txt", "README.txt"])

        self.assertIsNotNone(seen_rga_command)
        self.assertIn("!**/ANSWER.txt", seen_rga_command)
        self.assertIn("!ANSWER.txt", seen_rga_command)
        self.assertIn("!README.txt", seen_rga_command)

    @mock.patch("doc_triage.cli.run_command")
    def test_run_external_scanners_ignores_rga_adapter_failures(self, run_command: mock.Mock) -> None:
        run_command.side_effect = [
            cli.CommandResult(exit_code=0, stdout="", stderr="", timed_out=False),
            cli.CommandResult(
                exit_code=2,
                stdout="",
                stderr="rg: sample.pdf: preprocessor command failed",
                timed_out=False,
            ),
            cli.CommandResult(exit_code=0, stdout="", stderr="", timed_out=False),
        ]

        findings, warnings = cli.run_external_scanners(Path("/tmp/case"))

        self.assertEqual(findings, [])
        self.assertEqual(warnings, [])

    def test_render_priority_item_uses_fallback_reason_fields(self) -> None:
        item = {
            "source_path": "sequence/ctf/sequence.txt",
            "supporting_evidence": "__cfduid=...",
            "context": "Legacy Cloudflare cookie",
        }

        rendered = cli.render_priority_item(item)

        self.assertIn("sequence/ctf/sequence.txt", rendered)
        self.assertIn("Legacy Cloudflare cookie", rendered)

    def test_render_relationship_skips_empty_label_only_entries(self) -> None:
        rendered = cli.render_relationship({"type": "header_type"})

        self.assertEqual(rendered, [])

    def test_render_priority_item_skips_empty_reason_entries(self) -> None:
        rendered = cli.render_priority_item({"source_path": "sequence/ctf/sequence.txt"})

        self.assertEqual(rendered, "")

    @mock.patch("doc_triage.cli.urlopen")
    @mock.patch("doc_triage.cli.execute_helper_requests", return_value=([], []))
    @mock.patch("doc_triage.cli.generate_llm_helper_plan", return_value=[])
    def test_ollama_summary_parses_json_response(
        self,
        _: mock.Mock,
        __: mock.Mock,
        urlopen: mock.Mock,
    ) -> None:
        response = mock.Mock()
        response.__enter__ = mock.Mock(return_value=response)
        response.__exit__ = mock.Mock(return_value=False)
        response.read.return_value = json.dumps(
            {
                "response": json.dumps(
                    {
                        "executive_summary": "summary",
                        "priority_findings": [{"source": "a.txt", "why": "secret"}],
                        "relationships": [],
                        "review_order": ["a.txt"],
                    }
                )
            }
        ).encode("utf-8")
        urlopen.return_value = response

        result = cli.generate_llm_summary(
            "http://127.0.0.1:11434",
            "qwen3:8b",
            Path("/tmp/case"),
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

        self.assertEqual(result["executive_summary"], "summary")

    def test_execute_helper_requests_reads_file_heads(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            sample = target / "notes.txt"
            sample.write_text("line one\nline two\n", encoding="utf-8")

            results, warnings = cli.execute_helper_requests(
                target,
                [cli.HelperRequest(kind="read_head", path="notes.txt", reason="inspect text", limit=5)],
            )

        self.assertEqual(warnings, [])
        self.assertEqual(len(results), 1)
        self.assertIn("line one", results[0]["output"])

    def test_parse_helper_plan_limits_requests(self) -> None:
        payload = [{"kind": "read_head", "path": f"file-{index}.txt", "reason": "inspect"} for index in range(12)]

        requests = cli.parse_helper_plan(payload)

        self.assertEqual(len(requests), 8)

    @mock.patch("doc_triage.cli.generate_llm_summary")
    @mock.patch("doc_triage.cli.scan_target")
    def test_scan_includes_llm_summary_in_report(self, scan_target: mock.Mock, generate_llm_summary: mock.Mock) -> None:
        scan_target.return_value = (
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
            [],
        )
        generate_llm_summary.return_value = {
            "executive_summary": "LLM summary",
            "priority_findings": [{"source": "a.txt", "why": "Contains a password"}],
            "relationships": ["a.txt references internal access material"],
            "review_order": ["a.txt"],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir, "case")
            target.mkdir()
            output = Path(tmpdir, "report.md")

            exit_code = cli.main(["scan", str(target), "--output", str(output)])

            self.assertIn(exit_code, {0, 1})
            report = output.read_text(encoding="utf-8")
            self.assertIn("LLM summary", report)
            self.assertIn("Contains a password", report)
            self.assertIn("a.txt references internal access material", report)

    def test_render_report_formats_structured_llm_objects(self) -> None:
        args = cli.build_parser().parse_args(["scan", "/tmp/example"])
        finding = cli.Finding(
            source="a.txt",
            category="credential",
            severity="high",
            detector="rga",
            evidence="password=secret",
            line=1,
            confidence=0.9,
            metadata={},
        )
        llm_summary = {
            "executive_summary": "summary",
            "priority_findings": [
                {"source": "a.txt", "why": "Contains a password"},
                {"source_path": "b.txt", "description": "Contains an API token"},
                {"source_path": "c.txt", "claim": "Contains a suspicious cookie", "context": "Legacy cookie found"},
            ],
            "relationships": [
                {"type": "cross_domain", "description": "a.txt relates to b.txt", "source_paths": ["a.txt", "b.txt"]},
                {"relationship_type": "attribute_binding", "inference": "cookie binds to example.com", "source_path": "c.txt"},
                "legacy note",
            ],
            "review_order": ["a.txt", "b.txt"],
        }

        report = cli.render_report(args, Path("/tmp/example"), [finding], [], llm_summary=llm_summary)

        self.assertIn("a.txt: Contains a password", report)
        self.assertIn("b.txt: Contains an API token", report)
        self.assertIn("c.txt: Contains a suspicious cookie", report)
        self.assertIn("cross_domain: a.txt relates to b.txt", report)
        self.assertIn("Sources: a.txt, b.txt", report)
        self.assertIn("attribute_binding: cookie binds to example.com", report)
        self.assertIn("Sources: c.txt", report)

    def test_normalize_llm_summary_fills_missing_priority_sources_from_review_order(self) -> None:
        llm_summary = {
            "executive_summary": "summary",
            "priority_findings": [
                {"claim": "Contains a suspicious cookie"},
                {"description": "Contains a blockchain identifier"},
            ],
            "relationships": [],
            "review_order": ["sequence/ctf/sequence.txt", "bad_blockchain/ctf/bad-blockchain.txt"],
        }

        normalized = cli.normalize_llm_summary(llm_summary)

        self.assertEqual(
            normalized["priority_findings"][0]["source_path"],
            "sequence/ctf/sequence.txt",
        )
        self.assertEqual(
            normalized["priority_findings"][1]["source_path"],
            "bad_blockchain/ctf/bad-blockchain.txt",
        )

    def test_render_report_ignores_non_path_review_order_entries(self) -> None:
        args = cli.build_parser().parse_args(["scan", "/tmp/example"])
        finding = cli.Finding(
            source="a.txt",
            category="credential",
            severity="high",
            detector="rga",
            evidence="password=secret",
            line=1,
            confidence=0.9,
            metadata={},
        )
        llm_summary = {
            "executive_summary": "summary",
            "priority_findings": [{"source": "a.txt", "why": "Contains a password"}],
            "relationships": [],
            "review_order": [
                "1. Investigate timestamp first",
                "2. Cross-reference domain second",
            ],
        }

        report = cli.render_report(args, Path("/tmp/example"), [finding], [], llm_summary=llm_summary)

        self.assertIn("## Files Recommended for Manual Review", report)
        self.assertIn("- a.txt", report)
        self.assertNotIn("1. Investigate timestamp first", report)

    def test_render_terminal_report_highlights_evidence_and_preserves_full_text(self) -> None:
        report = "\n".join(
            [
                "# Sensitive Report",
                "",
                "## Ranked High-Value Findings",
                "- [high] credential in Finance/notes.txt:4 via rga",
                "  Evidence: `password=secret`",
                "",
                "## Files Recommended for Manual Review",
                "- Finance/notes.txt",
            ]
        )

        rendered = cli.render_terminal_report(report)

        self.assertIn("Sensitive Report", rendered)
        self.assertIn("password=", rendered)
        self.assertIn("\u001b[", rendered)
        self.assertIn(f"password={cli.colorize('secret', 'critical')}", rendered)

    def test_render_terminal_report_highlights_raw_secret_blobs(self) -> None:
        blob = "/ETA2urp4UnyL7jLGSgn9O3aZXb+fIqD36Nc1s8UygLIQ5cvCv4YPg687+OOwXoTc9xATUV+oKoTAYDwKskvxjmQ"
        report = "\n".join(
            [
                "# Sensitive Report",
                "",
                "## Secret and Credential Findings",
                "- [high] credential in handout.zip via trufflehog",
                f"  Evidence: `{blob}`",
            ]
        )

        rendered = cli.render_terminal_report(report)

        self.assertIn(cli.colorize(blob, "critical"), rendered)

    def test_render_terminal_report_highlights_file_password_value_only(self) -> None:
        report = "\n".join(
            [
                "# Sensitive Report",
                "",
                "## Secret and Credential Findings",
                "- [high] credential in README.md via pattern:password-assignment",
                "  Evidence: `File Password : 73c1818c4ee40dcc567fb5457f3ff9199714ee7272df573a59ae40113064b889`",
            ]
        )

        rendered = cli.render_terminal_report(report)

        self.assertIn("File Password :", rendered)
        self.assertIn(
            f"File Password : {cli.colorize('73c1818c4ee40dcc567fb5457f3ff9199714ee7272df573a59ae40113064b889', 'critical')}",
            rendered,
        )

    def test_render_terminal_report_highlights_shared_secret_value_only(self) -> None:
        report = "\n".join(
            [
                "# Sensitive Report",
                "",
                "## Secret and Credential Findings",
                "- [high] credential in secrets.env via pattern:shared-secret-assignment",
                "  Evidence: `shared_secret=DeltaBlue!2024`",
            ]
        )

        rendered = cli.render_terminal_report(report)

        self.assertIn("shared_secret=", rendered)
        self.assertIn(f"shared_secret={cli.colorize('DeltaBlue!2024', 'critical')}", rendered)

    def test_cli_standard_output_shows_progress_and_full_report(self) -> None:
        import subprocess

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "case"
            root.mkdir()
            (root / "secret.txt").write_text("password=secret\n", encoding="utf-8")
            report = Path(td) / "report.md"
            result = subprocess.run(
                ["python3", "-m", "doc_triage.cli", "scan", str(root), "--output", str(report), "--no-llm"],
                cwd="/home/seal/Documents/hackathon",
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

        self.assertEqual(result.returncode, 0)
        self.assertIn("[doc-triage] [scan] Starting scan", result.stdout)
        self.assertIn("Sensitive Report", result.stdout)
        self.assertIn("password=secret", result.stdout)


if __name__ == "__main__":
    unittest.main()
