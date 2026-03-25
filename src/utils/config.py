#!/usr/bin/env python3
"""
Configuration management for Supply Chain Guardian.
Reads all settings from environment variables set by the GitHub Action.
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ScanConfig:
    """Central configuration for all scanner modules."""

    # Core settings
    scan_mode: str = "standard"  # quick, standard, deep, paranoid
    fail_on_severity: str = "high"
    workspace_dir: str = "."
    verbose: bool = False

    # Scanner toggles
    scan_workflows: bool = True
    scan_dependencies: bool = True
    scan_secrets: bool = True
    scan_network: bool = True
    scan_permissions: bool = True
    scan_provenance: bool = True
    scan_runtime: bool = False

    # Custom rules
    custom_rules_path: str = ""
    exclude_paths: List[str] = field(default_factory=list)

    # Alerting
    slack_webhook_url: str = ""
    teams_webhook_url: str = ""
    alert_on_severity: str = "high"

    # Reporting
    sarif_output: bool = True
    json_output: bool = True
    json_output_path: str = "supply-chain-guardian-report.json"
    table_output: bool = True

    # GitHub integration
    github_token: str = ""
    block_pr: bool = True
    create_issue: bool = True
    auto_comment_pr: bool = True

    # Metadata
    repository: str = ""
    commit_sha: str = ""
    ref: str = ""
    event_name: str = ""
    run_id: str = ""
    server_url: str = ""

    @classmethod
    def from_environment(cls) -> 'ScanConfig':
        """Build config from environment variables (set by action.yml)."""

        def env_bool(key: str, default: bool = False) -> bool:
            val = os.environ.get(key, str(default)).lower()
            return val in ("true", "1", "yes")

        def env_str(key: str, default: str = "") -> str:
            return os.environ.get(key, default)

        def env_list(key: str, default: str = "") -> List[str]:
            val = os.environ.get(key, default)
            return [p.strip() for p in val.split(",") if p.strip()] if val else []

        workspace = env_str("GITHUB_WORKSPACE", os.getcwd())

        config = cls(
            scan_mode=env_str("INPUT_SCAN_MODE", "standard"),
            fail_on_severity=env_str("INPUT_FAIL_ON_SEVERITY", "high"),
            workspace_dir=workspace,
            verbose=env_bool("INPUT_VERBOSE", False) or env_str("INPUT_SCAN_MODE") == "paranoid",

            scan_workflows=env_bool("INPUT_SCAN_WORKFLOWS", True),
            scan_dependencies=env_bool("INPUT_SCAN_DEPENDENCIES", True),
            scan_secrets=env_bool("INPUT_SCAN_SECRETS", True),
            scan_network=env_bool("INPUT_SCAN_NETWORK", True),
            scan_permissions=env_bool("INPUT_SCAN_PERMISSIONS", True),
            scan_provenance=env_bool("INPUT_SCAN_PROVENANCE", True),
            scan_runtime=env_bool("INPUT_SCAN_RUNTIME", False),

            custom_rules_path=env_str("INPUT_CUSTOM_RULES_PATH"),
            exclude_paths=env_list("INPUT_EXCLUDE_PATHS"),

            slack_webhook_url=env_str("INPUT_SLACK_WEBHOOK_URL"),
            teams_webhook_url=env_str("INPUT_TEAMS_WEBHOOK_URL"),
            alert_on_severity=env_str("INPUT_ALERT_ON_SEVERITY", "high"),

            sarif_output=env_bool("INPUT_SARIF_OUTPUT", True),
            json_output=env_str("INPUT_JSON_OUTPUT") != "",
            json_output_path=env_str("INPUT_JSON_OUTPUT", "supply-chain-guardian-report.json"),
            table_output=env_bool("INPUT_TABLE_OUTPUT", True),

            github_token=env_str("INPUT_GITHUB_TOKEN"),
            block_pr=env_bool("INPUT_BLOCK_PR", True),
            create_issue=env_bool("INPUT_CREATE_ISSUE", True),
            auto_comment_pr=env_bool("INPUT_AUTO_COMMENT_PR", True),

            repository=env_str("GITHUB_REPOSITORY"),
            commit_sha=env_str("GITHUB_SHA"),
            ref=env_str("GITHUB_REF"),
            event_name=env_str("GITHUB_EVENT_NAME"),
            run_id=env_str("GITHUB_RUN_ID"),
            server_url=env_str("GITHUB_SERVER_URL", "https://github.com"),
        )

        return config

    @classmethod
    def from_cli_args(cls, args) -> 'ScanConfig':
        """Build config from CLI arguments."""
        config = cls(
            scan_mode=args.scan_mode,
            fail_on_severity=args.fail_on_severity,
            workspace_dir=args.target or os.getcwd(),
            verbose=args.verbose,
            scan_workflows=args.scan_workflows,
            scan_dependencies=args.scan_dependencies,
            scan_secrets=args.scan_secrets,
            scan_network=args.scan_network,
            scan_permissions=args.scan_permissions,
            scan_provenance=args.scan_provenance,
            scan_runtime=args.scan_runtime,
            custom_rules_path=getattr(args, 'custom_rules', ''),
            exclude_paths=[p.strip() for p in (args.exclude or "").split(",") if p.strip()],
            slack_webhook_url=getattr(args, 'slack_webhook', ''),
            teams_webhook_url=getattr(args, 'teams_webhook', ''),
            alert_on_severity=getattr(args, 'alert_severity', 'high'),
            sarif_output=getattr(args, 'sarif', True),
            json_output=bool(getattr(args, 'json_output', '')),
            json_output_path=getattr(args, 'json_output', 'supply-chain-guardian-report.json'),
            table_output=getattr(args, 'table', True),
        )
        return config

    def should_scan_path(self, path: str) -> bool:
        """Check if a path should be scanned (not excluded)."""
        for excl in self.exclude_paths:
            if excl in path:
                return False
        return True
