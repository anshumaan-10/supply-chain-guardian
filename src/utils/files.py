#!/usr/bin/env python3
"""
File utilities for Supply Chain Guardian.
Safely reads and parses workflow files, package manifests, etc.
"""

import os
import yaml
import json
import re
from pathlib import Path
from typing import List, Dict, Optional, Any


def _get_extra_scan_dirs(workspace: str) -> List[str]:
    """Resolve extra scan path directories from INPUT_EXTRA_SCAN_PATHS env var."""
    raw = os.environ.get("INPUT_EXTRA_SCAN_PATHS", "")
    dirs = []
    for p in raw.split(","):
        p = p.strip()
        if not p:
            continue
        resolved = os.path.join(workspace, p) if not os.path.isabs(p) else p
        if os.path.isdir(resolved):
            dirs.append(resolved)
    return dirs


def find_workflow_files(workspace: str) -> List[str]:
    """Find all GitHub Actions workflow files, including extra scan paths."""
    workflows_dir = os.path.join(workspace, ".github", "workflows")
    files = []
    if os.path.isdir(workflows_dir):
        for f in os.listdir(workflows_dir):
            if f.endswith((".yml", ".yaml")):
                files.append(os.path.join(workflows_dir, f))

    # Include yml/yaml from extra scan directories
    for extra_dir in _get_extra_scan_dirs(workspace):
        for root, dirs, filenames in os.walk(extra_dir):
            dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', '__pycache__', '.venv')]
            for f in filenames:
                if f.endswith((".yml", ".yaml")):
                    full = os.path.join(root, f)
                    if full not in files:
                        files.append(full)

    return files


def find_action_files(workspace: str) -> List[str]:
    """Find all action.yml/action.yaml files (composite actions)."""
    files = []
    for root, dirs, filenames in os.walk(workspace):
        # Skip node_modules, .git, etc.
        dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', '__pycache__', '.venv')]
        for f in filenames:
            if f in ('action.yml', 'action.yaml'):
                files.append(os.path.join(root, f))
    return files


def _sanitize_gha_expressions(content: str) -> str:
    """Replace ${{ ... }} with quoted placeholder preserving expression text."""
    def _replacer(m):
        expr = m.group(1).strip()
        # Use a safe placeholder that preserves the expression content for analysis
        safe = expr.replace('"', "'")
        return f'"GHA_EXPR:{safe}"'
    return re.sub(r'\$\{\{(.*?)\}\}', _replacer, content)


def parse_yaml_safe(filepath: str) -> Optional[Dict]:
    """Safely parse a YAML file, handling GitHub Actions ${{ }} expressions."""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        sanitized = _sanitize_gha_expressions(content)
        return yaml.safe_load(sanitized)
    except Exception:
        return None


def read_file_lines(filepath: str) -> List[str]:
    """Read a file into lines."""
    try:
        with open(filepath, 'r', errors='replace') as f:
            return f.readlines()
    except Exception:
        return []


def find_package_files(workspace: str) -> Dict[str, List[str]]:
    """Find all package manifest files by ecosystem.
    Uses substring matching to find files with prefixed names (e.g. 07-package.json)."""
    result = {
        "npm": [],
        "python": [],
        "go": [],
        "ruby": [],
        "rust": [],
        "java": [],
    }

    for root, dirs, files in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', '__pycache__', '.venv', 'vendor')]
        rel = os.path.relpath(root, workspace)

        for f in files:
            path = os.path.join(root, f)
            fl = f.lower()
            # npm ecosystem
            if f == "package.json" or (fl.endswith("package.json") and "lock" not in fl):
                result["npm"].append(path)
            elif f == "package-lock.json" or fl.endswith("package-lock.json"):
                result["npm"].append(path)
            # Python ecosystem
            elif f in ("requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "setup.py", "setup.cfg") \
                    or fl.endswith("requirements.txt") or fl.endswith("setup.py") or fl.endswith("pyproject.toml"):
                result["python"].append(path)
            # Go
            elif f in ("go.mod", "go.sum"):
                result["go"].append(path)
            # Ruby
            elif f in ("Gemfile", "Gemfile.lock"):
                result["ruby"].append(path)
            # Rust
            elif f in ("Cargo.toml", "Cargo.lock"):
                result["rust"].append(path)
            # Java
            elif f in ("pom.xml", "build.gradle", "build.gradle.kts"):
                result["java"].append(path)

    return result


def extract_uses_statements(filepath: str) -> List[Dict[str, Any]]:
    """Extract all 'uses:' statements from a workflow file with line numbers."""
    lines = read_file_lines(filepath)
    results = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("uses:") or "uses:" in stripped:
            match = re.search(r'uses:\s*["\']?([^"\'#\s]+)', stripped)
            if match:
                action_ref = match.group(1).strip()
                results.append({
                    "line": i,
                    "raw": stripped,
                    "action_ref": action_ref,
                    "file": filepath
                })
    return results


def extract_run_blocks(filepath: str) -> List[Dict[str, Any]]:
    """Extract all 'run:' blocks from a workflow file with content."""
    lines = read_file_lines(filepath)
    results = []
    in_run = False
    run_start = 0
    run_content = []
    indent_level = 0

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        current_indent = len(line) - len(line.lstrip())

        if re.match(r'^-?\s*run:\s*\|', stripped):
            if in_run and run_content:
                results.append({
                    "line": run_start,
                    "content": "\n".join(run_content),
                    "file": filepath
                })
            in_run = True
            run_start = i
            run_content = []
            indent_level = current_indent + 2
        elif re.match(r'^-?\s*run:\s*\S', stripped):
            # Single-line run
            run_cmd = re.sub(r'^-?\s*run:\s*', '', stripped)
            results.append({
                "line": i,
                "content": run_cmd,
                "file": filepath
            })
        elif in_run:
            if current_indent >= indent_level and stripped:
                run_content.append(stripped)
            elif not stripped:
                run_content.append("")
            else:
                if run_content:
                    results.append({
                        "line": run_start,
                        "content": "\n".join(run_content),
                        "file": filepath
                    })
                in_run = False
                run_content = []

    if in_run and run_content:
        results.append({
            "line": run_start,
            "content": "\n".join(run_content),
            "file": filepath
        })

    return results


def relative_path(filepath: str, workspace: str) -> str:
    """Get relative path from workspace root."""
    try:
        return os.path.relpath(filepath, workspace)
    except ValueError:
        return filepath


def find_jenkinsfiles(workspace: str) -> List[str]:
    """Find all Jenkinsfile and Jenkins pipeline files (including prefixed names)."""
    files = []
    for root, dirs, filenames in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', '__pycache__', '.venv')]
        for f in filenames:
            fl = f.lower()
            if fl == 'jenkinsfile' or fl.endswith('jenkinsfile') or fl.endswith('.jenkinsfile'):
                files.append(os.path.join(root, f))
    return files


def find_gitlab_ci_files(workspace: str) -> List[str]:
    """Find all GitLab CI configuration files (including prefixed names)."""
    files = []
    # Main config
    main_ci = os.path.join(workspace, ".gitlab-ci.yml")
    if os.path.isfile(main_ci):
        files.append(main_ci)
    # Included templates
    ci_dir = os.path.join(workspace, ".gitlab", "ci")
    if os.path.isdir(ci_dir):
        for root, dirs, filenames in os.walk(ci_dir):
            for f in filenames:
                if f.endswith((".yml", ".yaml")):
                    files.append(os.path.join(root, f))
    # Extra scan paths: find files with 'gitlab-ci' in the name
    for extra_dir in _get_extra_scan_dirs(workspace):
        for root, dirs, filenames in os.walk(extra_dir):
            dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', '__pycache__', '.venv')]
            for f in filenames:
                if 'gitlab-ci' in f.lower() and f.endswith((".yml", ".yaml")):
                    full = os.path.join(root, f)
                    if full not in files:
                        files.append(full)
    return files


def find_circleci_files(workspace: str) -> List[str]:
    """Find all CircleCI configuration files (including prefixed names)."""
    files = []
    circleci_dir = os.path.join(workspace, ".circleci")
    if os.path.isdir(circleci_dir):
        for f in os.listdir(circleci_dir):
            if f.endswith((".yml", ".yaml")):
                files.append(os.path.join(circleci_dir, f))
    # Extra scan paths: find files with 'circleci' in the name
    for extra_dir in _get_extra_scan_dirs(workspace):
        for root, dirs, filenames in os.walk(extra_dir):
            dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', '__pycache__', '.venv')]
            for f in filenames:
                if 'circleci' in f.lower() and f.endswith((".yml", ".yaml")):
                    full = os.path.join(root, f)
                    if full not in files:
                        files.append(full)
    return files


def find_azure_pipelines(workspace: str) -> List[str]:
    """Find all Azure DevOps pipeline files (including prefixed names)."""
    files = []
    # Standard name
    for name in ("azure-pipelines.yml", "azure-pipelines.yaml"):
        path = os.path.join(workspace, name)
        if os.path.isfile(path):
            files.append(path)
    # Pipeline templates in .azure-pipelines/
    azure_dir = os.path.join(workspace, ".azure-pipelines")
    if os.path.isdir(azure_dir):
        for f in os.listdir(azure_dir):
            if f.endswith((".yml", ".yaml")):
                files.append(os.path.join(azure_dir, f))
    # Extra scan paths: find files with 'azure-pipeline' in the name
    for extra_dir in _get_extra_scan_dirs(workspace):
        for root, dirs, filenames in os.walk(extra_dir):
            dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', '__pycache__', '.venv')]
            for f in filenames:
                if 'azure-pipeline' in f.lower() and f.endswith((".yml", ".yaml")):
                    full = os.path.join(root, f)
                    if full not in files:
                        files.append(full)
    return files


def find_all_ci_files(workspace: str) -> Dict[str, List[str]]:
    """Find all CI/CD configuration files across all platforms."""
    return {
        "github_actions": find_workflow_files(workspace) + find_action_files(workspace),
        "jenkins": find_jenkinsfiles(workspace),
        "gitlab_ci": find_gitlab_ci_files(workspace),
        "circleci": find_circleci_files(workspace),
        "azure_devops": find_azure_pipelines(workspace),
    }
