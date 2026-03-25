#!/usr/bin/env python3
"""
JSON Reporter
=============
Writes scan results as structured JSON for downstream
processing and artifact storage.
"""

import json
from typing import Dict, Any


class JsonReporter:
    """Generate JSON report output."""

    @staticmethod
    def write_report(report_data: Dict[str, Any], output_path: str) -> bool:
        """Write JSON report to file."""
        try:
            with open(output_path, "w") as f:
                json.dump(report_data, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"  Error writing JSON report: {e}")
            return False

    @staticmethod
    def to_json_string(report_data: Dict[str, Any]) -> str:
        """Return JSON report as string."""
        return json.dumps(report_data, indent=2, default=str)
