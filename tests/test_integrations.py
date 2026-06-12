import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from doc_triage import cli


class IntegrationTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
