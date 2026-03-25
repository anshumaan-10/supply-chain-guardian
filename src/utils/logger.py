#!/usr/bin/env python3
"""
Logging utilities for Supply Chain Guardian.
Colorized output with GitHub Actions annotation support.
"""

import sys
import os


class Colors:
    """ANSI color codes for terminal output."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY or CI)."""
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = ""
        cls.MAGENTA = cls.CYAN = cls.WHITE = cls.BOLD = cls.DIM = cls.RESET = ""


# Disable colors if not a TTY and not GitHub Actions
if not sys.stdout.isatty() and os.environ.get("GITHUB_ACTIONS") != "true":
    Colors.disable()


class Logger:
    """Structured logger with color and GitHub Actions annotation support."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.is_github = os.environ.get("GITHUB_ACTIONS") == "true"

    def info(self, msg: str):
        print(f"  {Colors.CYAN}ℹ{Colors.RESET}  {msg}")

    def success(self, msg: str):
        print(f"  {Colors.GREEN}✅{Colors.RESET} {msg}")

    def warning(self, msg: str):
        print(f"  {Colors.YELLOW}⚠️{Colors.RESET}  {msg}")
        if self.is_github:
            print(f"::warning::{msg}")

    def error(self, msg: str):
        print(f"  {Colors.RED}❌{Colors.RESET} {msg}")
        if self.is_github:
            print(f"::error::{msg}")

    def critical(self, msg: str):
        print(f"  {Colors.RED}{Colors.BOLD}🚨 CRITICAL:{Colors.RESET} {Colors.RED}{msg}{Colors.RESET}")
        if self.is_github:
            print(f"::error title=SUPPLY CHAIN ATTACK DETECTED::{msg}")

    def debug(self, msg: str):
        if self.verbose:
            print(f"  {Colors.DIM}[DEBUG] {msg}{Colors.RESET}")

    def section(self, title: str):
        line = "═" * 60
        print(f"\n  {Colors.BOLD}{Colors.CYAN}╔{line}╗{Colors.RESET}")
        print(f"  {Colors.BOLD}{Colors.CYAN}║{Colors.RESET} {Colors.BOLD}{title.center(58)}{Colors.RESET} {Colors.BOLD}{Colors.CYAN}║{Colors.RESET}")
        print(f"  {Colors.BOLD}{Colors.CYAN}╚{line}╝{Colors.RESET}")

    def finding(self, severity: str, scanner: str, title: str, details: str = ""):
        sev_colors = {
            "critical": Colors.RED + Colors.BOLD,
            "high": Colors.RED,
            "medium": Colors.YELLOW,
            "low": Colors.BLUE,
            "info": Colors.DIM
        }
        color = sev_colors.get(severity, Colors.WHITE)
        icon = {"critical": "🚨", "high": "🔴", "medium": "🟡", "low": "🔵", "info": "ℹ️"}.get(severity, "•")
        print(f"    {icon} {color}[{severity.upper()}]{Colors.RESET} [{scanner}] {title}")
        if details:
            print(f"       {Colors.DIM}{details}{Colors.RESET}")
