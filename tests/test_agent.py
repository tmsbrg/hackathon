import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest import mock

from doc_triage import cli


class AgentModeTests(unittest.TestCase):
    def test_scan_rejects_agent_with_no_llm(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            exit_code = cli.main(["scan", tmpdir, "--agent", "--no-llm"])

        self.assertEqual(exit_code, cli.EXIT_USAGE)

    @mock.patch("doc_triage.cli.run_agent_mode")
    @mock.patch("doc_triage.cli.scan_target", return_value=([], []))
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
    def test_agent_mode_runs_without_deterministic_findings(
        self,
        _: mock.Mock,
        __: mock.Mock,
        run_agent_mode: mock.Mock,
    ) -> None:
        run_agent_mode.return_value = cli.AgentRun()
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir, "case")
            target.mkdir()
            (target / "plain.txt").write_text("hello\n", encoding="utf-8")
            output = Path(tmpdir, "report.md")

            exit_code = cli.main(["scan", str(target), "--output", str(output), "--agent"])

        self.assertEqual(exit_code, cli.EXIT_OK)
        run_agent_mode.assert_called_once()

    def test_build_agent_recon_context_samples_representative_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            (target / "docs").mkdir()
            (target / "media").mkdir()
            (target / "docs" / "alpha.txt").write_text("first\n", encoding="utf-8")
            (target / "docs" / "beta.json").write_text('{"secret": "x"}\n', encoding="utf-8")
            (target / "media" / "image.jpg").write_bytes(b"\xff\xd8\xff")
            (target / "sample.pdf").write_text("fake pdf\n", encoding="utf-8")

            recon = cli.build_agent_recon_context(target, [], max_files=10)

        representative = {item["path"] for item in recon["representative_heads"]}
        self.assertIn("docs/alpha.txt", representative)
        self.assertIn("docs/beta.json", representative)

    def test_deduplicate_agent_actions_preserves_first_unique_action(self) -> None:
        actions = [
            cli.AgentAction(kind="read_head", path="a.txt", reason="first"),
            cli.AgentAction(kind="read_head", path="a.txt", reason="duplicate"),
            cli.AgentAction(kind="dir_list", path="docs", reason="unique"),
        ]

        deduped = cli.deduplicate_agent_actions(actions)

        self.assertEqual(len(deduped), 2)
        self.assertEqual(deduped[0].reason, "first")

    def test_build_fallback_agent_plan_uses_findings_and_representative_files(self) -> None:
        recon = {
            "top_directories": [{"path": "docs", "count": 4}],
            "representative_heads": [{"path": "docs/a.txt", "preview": "hello"}],
        }
        findings = [
            cli.Finding(
                source="loot.txt",
                category="credential",
                severity="high",
                detector="built-in",
                evidence="session token=abc",
                line=1,
                confidence=0.9,
                metadata={},
            )
        ]

        hypotheses, actions = cli.build_fallback_agent_plan(Path("/tmp/case"), findings, recon, action_budget=5)

        self.assertTrue(hypotheses)
        self.assertTrue(any(action.kind == "content_search" for action in actions))
        self.assertTrue(any(action.path == "loot.txt" for action in actions))

    @mock.patch("doc_triage.cli.run_command")
    def test_execute_agent_actions_normalizes_content_search_results(self, run_command: mock.Mock) -> None:
        run_command.return_value = cli.CommandResult(
            exit_code=0,
            stdout="alpha.txt:2:token=secret\n",
            stderr="",
            timed_out=False,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            observations, warnings = cli.execute_agent_actions(
                target,
                [cli.AgentAction(kind="content_search", query="token", reason="look for tokens", limit=5)],
                per_action_timeout=5,
            )

        self.assertEqual(warnings, [])
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].path, "alpha.txt")
        self.assertEqual(observations[0].source_mechanism, "content_search")

    def test_validate_generated_helper_source_rejects_unsafe_constructs(self) -> None:
        errors = cli.validate_generated_helper_source("import subprocess\nprint('nope')\n")

        self.assertTrue(errors)
        self.assertIn("subprocess", " ".join(errors))

    @mock.patch("doc_triage.cli.shutil.which", return_value=None)
    def test_execute_generated_helper_warns_when_bwrap_missing(self, _: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            observations, warnings = cli.execute_generated_helper(
                Path(tmpdir),
                cli.AgentAction(
                    kind="generated_python_helper",
                    reason="inspect",
                    code='print("{\\"path\\": \\"a.txt\\", \\"evidence\\": \\"x\\"}")\n',
                ),
                timeout_seconds=5,
            )

        self.assertEqual(observations, [])
        self.assertIn("generated helpers skipped", " ".join(warnings))

    def test_render_report_includes_agent_sections(self) -> None:
        args = cli.build_parser().parse_args(["scan", "/tmp/case", "--agent"])
        agent_run = cli.AgentRun(
            hypotheses=[cli.AgentHypothesis(label="archive contains credentials", rationale="zip nearby")],
            actions=[cli.AgentAction(kind="dir_list", path=".", reason="survey root")],
            observations=[
                cli.AgentObservation(
                    path="docs/a.txt",
                    evidence="password=secret",
                    source_mechanism="read_head",
                    confidence=0.9,
                    derived_claim="Contains a password",
                )
            ],
            warnings=["agent sandbox unavailable; generated helpers skipped"],
        )

        report = cli.render_report(args, Path("/tmp/case"), [], [], llm_summary=None, agent_run=agent_run)

        self.assertIn("## Agent Investigation Plan", report)
        self.assertIn("## Agent Observations", report)
        self.assertIn("## Agent Coverage and Limitations", report)

    def test_summarize_findings_includes_agent_stats(self) -> None:
        agent_run = cli.AgentRun(
            hypotheses=[cli.AgentHypothesis(label="test", rationale="test", status="confirmed")],
            actions=[cli.AgentAction(kind="read_head", path="a.txt", reason="inspect")],
            observations=[
                cli.AgentObservation(
                    path="a.txt",
                    evidence="password=secret",
                    source_mechanism="read_head",
                    confidence=0.95,
                    derived_claim="Contains a credential",
                )
            ],
        )

        rendered = "\n".join(cli.summarize_findings([], [], agent_run=agent_run))

        self.assertIn("Agent mode", rendered)
        self.assertIn("password=secret", rendered)


if __name__ == "__main__":
    unittest.main()
