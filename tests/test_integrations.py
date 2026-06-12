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

    @mock.patch("doc_triage.cli.urlopen")
    def test_ollama_summary_parses_json_response(self, urlopen: mock.Mock) -> None:
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


if __name__ == "__main__":
    unittest.main()
