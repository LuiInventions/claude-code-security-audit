"""Korreliert Findings run-weit und erzeugt kombinierte Risikoketten."""
from __future__ import annotations

import json
import sys
from collections import defaultdict

from auditlib import build_finding, default_target, iter_run_json, now_iso, write_script_output, write_text_artifact


def load_findings() -> list[dict]:
    findings: list[dict] = []
    for file_path in iter_run_json(latest_only=True):
        if file_path.name.startswith("32_report_correlator_"):
            continue
        data = json.loads(file_path.read_text(encoding="utf-8"))
        for item in data.get("findings", []):
            item["_script"] = data.get("script", "")
            findings.append(item)
    return findings


def correlate(target: str) -> tuple[list[dict], dict]:
    findings = load_findings()
    correlations: list[dict] = []
    grouped = defaultdict(list)
    for finding in findings:
        grouped[finding.get("target", target)].append(finding)

    for finding_target, items in grouped.items():
        titles = " | ".join(item.get("title", "") for item in items)
        if "Unsanitized Reflection erkannt" in titles and "CSP erlaubt 'unsafe-inline'" in titles:
            correlations.append(
                build_finding(
                    f"F-CORR-XSS-{abs(hash(finding_target)) & 0xFFFF}",
                    finding_target,
                    "Kombinierte XSS-Risikokette",
                    "High",
                    description="Unsanitized Reflection trifft auf eine geschwaechte CSP und erhoeht die reale Ausnutzbarkeit deutlich.",
                    affected_findings=[item.get("id") for item in items if item.get("id")],
                )
            )
        if any("Rate-Limit" in item.get("title", "") for item in items) and any("Auth" in item.get("title", "") or "Authentifizierungs" in item.get("title", "") for item in items):
            correlations.append(
                build_finding(
                    f"F-CORR-AUTH-ABUSE-{abs(hash(finding_target)) & 0xFFFF}",
                    finding_target,
                    "Kombinierte Abuse-Kette auf Auth-Workflows",
                    "High",
                    description="Schwache Auth-Oberflaechen und fehlende Drosselung erhoehen Missbrauchs- und Automatisierungsrisiken.",
                    affected_findings=[item.get("id") for item in items if item.get("id")],
                )
            )

    summary = {
        "total_findings": len(findings),
        "correlations": len(correlations),
        "targets": len(grouped),
    }
    return correlations, summary


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    findings, summary = correlate(target)
    write_text_artifact("summary.json", json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    payload = {"script": "32_report_correlator.py", "timestamp": now_iso(), "target": target, "findings": findings}
    filename = write_script_output("32_correlator", payload)
    print(f"[+] {len(payload['findings'])} findings -> {filename}")
