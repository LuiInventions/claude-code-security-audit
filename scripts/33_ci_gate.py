"""Einfaches CI-Gate fuer Severity-Schwellen."""
from __future__ import annotations

import json
import sys

from auditlib import iter_run_json

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def main() -> int:
    threshold = sys.argv[1] if len(sys.argv) > 1 else "High"
    findings = []
    for file_path in iter_run_json(latest_only=True):
        data = json.loads(file_path.read_text(encoding="utf-8"))
        findings.extend(data.get("findings", []))
    hits = [item for item in findings if SEVERITY_ORDER.get(item.get("severity", "Info"), 0) >= SEVERITY_ORDER.get(threshold, 3)]
    print(json.dumps({"threshold": threshold, "matching_findings": len(hits)}, ensure_ascii=False))
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
