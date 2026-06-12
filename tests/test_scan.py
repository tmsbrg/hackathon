import tempfile
import unittest
from pathlib import Path
from unittest import mock

from doc_triage import cli


class ScanLogicTests(unittest.TestCase):
    def test_bsn_validator_accepts_valid_value(self) -> None:
        self.assertTrue(cli.is_valid_bsn("123456782"))

    def test_bsn_validator_rejects_invalid_value(self) -> None:
        self.assertFalse(cli.is_valid_bsn("123456789"))

    def test_extract_digit_runs_only_returns_standalone_nine_digit_values(self) -> None:
        values = cli.extract_digit_runs("cookie=abc856516016def bsn 123456782 hash4a616f9437")

        self.assertEqual(values, ["123456782"])

    def test_keyword_findings_suppresses_invalid_bsn_testing_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            path = target / "records.json"
            path.write_text('{"note":"SANDBOX - invalid BSN for testing","bsn":"999999999"}\n', encoding="utf-8")

            findings = cli.keyword_findings(target, path, path.read_text(encoding="utf-8"))

        self.assertEqual(findings, [])

    def test_keyword_findings_detects_contextual_ocr_password_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            path = target / "ocr.txt"
            path.write_text(
                "Integration settings (do not share):\n\n"
                "F}&: wms_service\n"
                "2255: ShaWMS-2024-Rot\n",
                encoding="utf-8",
            )

            findings = cli.keyword_findings(target, path, path.read_text(encoding="utf-8"))

        self.assertTrue(any(f.detector == "contextual-ocr-credential" for f in findings))
        self.assertTrue(any("ShaWMS-2024-Rot" in f.evidence for f in findings))

    def test_classify_match_detects_http_only_cookie(self) -> None:
        classification = cli.classify_match(
            '"set-cookie" : "__cfduid=abc; expires=Mon, 27-Jun-16 15:56:37 GMT; path=/; domain=.example.com; HttpOnly",'
        )

        self.assertEqual(classification, ("credential", "high", 0.9))

    def test_keyword_findings_detect_multilingual_password_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            path = target / "config.txt"
            path.write_text(
                "mot de passe: bonjour123\n"
                "contraseña=secreto123\n"
                "пароль: qwerty123\n"
                "密码: Zhongwen123\n"
                "private_key=abc123secret\n",
                encoding="utf-8",
            )

            findings = cli.keyword_findings(target, path, path.read_text(encoding="utf-8"))

        detectors = {finding.detector for finding in findings}
        self.assertIn("pattern:french-password-assignment", detectors)
        self.assertIn("pattern:spanish-password-assignment", detectors)
        self.assertIn("pattern:global-password-assignment", detectors)
        self.assertIn("pattern:credential-field-assignment", detectors)

    def test_keyword_findings_detect_multilingual_credential_and_username_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            path = target / "directory.txt"
            path.write_text(
                "identifiants: analyste\n"
                "aanmeldgegevens: vpn-user\n"
                "ログイン情報: operator\n"
                "gebruikersnaam: mulder\n",
                encoding="utf-8",
            )

            findings = cli.keyword_findings(target, path, path.read_text(encoding="utf-8"))

        detectors = {finding.detector for finding in findings}
        self.assertIn("pattern:credentials-assignment", detectors)
        self.assertIn("pattern:username-assignment", detectors)

    def test_keyword_findings_detect_new_localized_credential_assignments(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            path = target / "localized.txt"
            path.write_text(
                "wachtwoorden: Welkom123\n"
                "geheimnis=netzwerk2024\n"
                "credenciales: operador-vpn\n",
                encoding="utf-8",
            )

            findings = cli.keyword_findings(target, path, path.read_text(encoding="utf-8"))

        detectors = {finding.detector for finding in findings}
        self.assertIn("pattern:credentials-assignment", detectors)
        self.assertIn("pattern:wachtwoord-assignment", detectors)
        self.assertIn("pattern:german-password-assignment", detectors)

    def test_keyword_findings_detect_seeded_credential_field_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            path = target / "secrets.env"
            path.write_text(
                "shared_secret=DeltaBlue!2024\n"
                "client_secret=tenant-client-secret\n"
                "pass=Welkom123\n",
                encoding="utf-8",
            )

            findings = cli.keyword_findings(target, path, path.read_text(encoding="utf-8"))

        detectors = {finding.detector for finding in findings}
        self.assertIn("pattern:shared-secret-assignment", detectors)
        self.assertIn("pattern:secret-assignment", detectors)
        self.assertIn("pattern:credential-field-assignment", detectors)

    def test_deduplicate_findings_collapses_same_source_category_and_evidence(self) -> None:
        findings = [
            cli.Finding(
                source="a.txt",
                category="credential",
                severity="high",
                detector="rga",
                evidence="password=secret",
                line=1,
                confidence=0.9,
                metadata={},
            ),
            cli.Finding(
                source="a.txt",
                category="credential",
                severity="medium",
                detector="built-in",
                evidence="password=secret",
                line=8,
                confidence=0.2,
                metadata={},
            ),
        ]

        deduped = cli.deduplicate_findings(findings)

        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0].severity, "high")
        self.assertEqual(deduped[0].detector, "rga")

    def test_deduplicate_findings_collapses_same_sensitive_value_from_same_file(self) -> None:
        findings = [
            cli.Finding(
                source="a.txt",
                category="credential",
                severity="high",
                detector="built-in",
                evidence="password=Welkom123",
                line=1,
                confidence=0.9,
                metadata={},
            ),
            cli.Finding(
                source="a.txt",
                category="credential",
                severity="medium",
                detector="trufflehog",
                evidence="Welkom123",
                line=None,
                confidence=0.8,
                metadata={},
            ),
        ]

        deduped = cli.deduplicate_findings(findings)

        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0].evidence, "password=Welkom123")

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    def test_scan_target_marks_sensitive_filenames_even_without_text_hits(self, _: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            secret_file = target / "id_rsa"
            secret_file.write_text("placeholder\n", encoding="utf-8")

            findings, warnings = cli.scan_target(target, max_files=None)

            self.assertEqual(warnings, [])
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].category, "sensitive-file")

    @mock.patch("doc_triage.cli.run_external_scanners")
    def test_scan_target_can_disable_dedup(self, run_external_scanners: mock.Mock) -> None:
        run_external_scanners.return_value = (
            [
                cli.Finding(
                    source="note.txt",
                    category="credential",
                    severity="high",
                    detector="rga",
                    evidence="password=Welkom123",
                    line=1,
                    confidence=0.9,
                    metadata={},
                ),
                cli.Finding(
                    source="note.txt",
                    category="credential",
                    severity="medium",
                    detector="trufflehog",
                    evidence="Welkom123",
                    line=None,
                    confidence=0.8,
                    metadata={},
                ),
            ],
            [],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            (target / "note.txt").write_text("password=Welkom123\n", encoding="utf-8")

            findings, warnings = cli.scan_target(target, max_files=None, dedup=False)

        self.assertEqual(warnings, [])
        self.assertGreaterEqual(len(findings), 2)
        self.assertTrue(any(item.detector == "rga" for item in findings))
        self.assertTrue(any(item.detector == "trufflehog" for item in findings))

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    def test_scan_target_ignores_office_lockfiles(self, _: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            lockfile = target / "~$VPN_toegang_2024.docx"
            lockfile.write_bytes(b"not a zip")

            findings, warnings = cli.scan_target(target, max_files=None)

            self.assertEqual(findings, [])
            self.assertEqual(warnings, [])

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    def test_scan_target_does_not_flag_generic_secret_titles(self, _: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            readme = target / "README.md"
            readme.write_text("Trinity Of Secrets\n", encoding="utf-8")

            findings, warnings = cli.scan_target(target, max_files=None)

            self.assertEqual(warnings, [])
            self.assertEqual(findings, [])

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    def test_scan_target_supports_all_documented_text_extensions(self, _: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            expected_sources = set()
            for suffix in sorted(cli.TEXT_EXTENSIONS):
                sample = target / f"sample{suffix}"
                sample.write_text("password=secret\n", encoding="utf-8")
                expected_sources.add(f"sample{suffix}")

            findings, warnings = cli.scan_target(target, max_files=None)

        self.assertEqual(warnings, [])
        found_sources = {finding.source for finding in findings}
        self.assertTrue(expected_sources.issubset(found_sources))

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    def test_scan_target_supports_all_documented_sensitive_filenames(self, _: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            for name in sorted(cli.SENSITIVE_FILENAMES):
                (target / name).write_text("placeholder\n", encoding="utf-8")

            findings, warnings = cli.scan_target(target, max_files=None)

        self.assertEqual(warnings, [])
        found_sources = {finding.source for finding in findings}
        self.assertTrue(set(cli.SENSITIVE_FILENAMES).issubset(found_sources))

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    def test_scan_target_marks_sensitive_path_suffixes(self, _: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            aws = target / ".aws" / "credentials"
            kube = target / ".kube" / "config"
            docker = target / ".docker" / "config.json"
            for path in (aws, kube, docker):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("placeholder\n", encoding="utf-8")

            findings, warnings = cli.scan_target(target, max_files=None)

        self.assertEqual(warnings, [])
        found_sources = {finding.source for finding in findings}
        self.assertIn(".aws/credentials", found_sources)
        self.assertIn(".kube/config", found_sources)
        self.assertIn(".docker/config.json", found_sources)

    @mock.patch("doc_triage.cli.run_external_scanners", return_value=([], []))
    def test_scan_target_marks_sensitive_extensions(self, _: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            pem = target / "certificate.pem"
            kdbx = target / "vault.kdbx"
            for path in (pem, kdbx):
                path.write_text("placeholder\n", encoding="utf-8")

            findings, warnings = cli.scan_target(target, max_files=None)

        self.assertEqual(warnings, [])
        found_sources = {finding.source for finding in findings}
        self.assertIn("certificate.pem", found_sources)
        self.assertIn("vault.kdbx", found_sources)

    def test_render_report_contains_expected_sections(self) -> None:
        args = cli.build_parser().parse_args(["scan", "/tmp/example", "--no-llm"])
        finding = cli.Finding(
            source="Finance/notes.txt",
            category="credential",
            severity="high",
            detector="rga",
            evidence="password=secret",
            line=4,
            confidence=0.95,
            metadata={},
        )

        report = cli.render_report(args, Path("/tmp/example"), [finding], [])

        self.assertIn("## Scope", report)
        self.assertIn("## Ranked High-Value Findings", report)
        self.assertIn("Finance/notes.txt", report)
        self.assertIn("password=secret", report)


if __name__ == "__main__":
    unittest.main()
