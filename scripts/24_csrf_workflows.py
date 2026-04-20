"""Analysiert state-changing Formulare und Workflows auf fehlenden CSRF-Schutz."""
from __future__ import annotations

import sys

from auditlib import build_finding, default_target, load_inventory, now_iso, write_script_output


def audit(target: str) -> list[dict]:
    inventory = load_inventory()
    findings: list[dict] = []
    forms = inventory.get("forms", [])

    for form in forms:
        method = form.get("method", "GET").upper()
        action = form.get("action", form.get("page", target))
        if method not in ("POST", "PUT", "PATCH", "DELETE"):
            continue
        fields = [field.lower() for field in form.get("fields", [])]
        if not form.get("has_csrf_token"):
            severity = "High" if any(word in action.lower() for word in ("account", "profile", "checkout", "password")) else "Medium"
            findings.append(
                build_finding(
                    f"F-CSRF-NOTOKEN-{abs(hash(action)) & 0xFFFF}",
                    action,
                    "State-Changing Formular ohne erkennbares CSRF-Token",
                    severity,
                    description="Mutierender Workflow zeigt keinen offensichtlichen synchronen CSRF-Schutz.",
                    evidence=f"Methode {method}, Fields: {fields}",
                    cwe="CWE-352",
                )
            )
        if method == "POST" and "origin" not in fields and "referer" not in fields and "csrf" not in " ".join(fields):
            findings.append(
                build_finding(
                    f"F-CSRF-WEAK-{abs(hash(action)) & 0xFFFF}",
                    action,
                    "Form-Workflow ohne sichtbare Herkunftsbindung",
                    "Low",
                    description="Es ist kein Hinweis auf Token- oder Herkunftsbindung im Formular erkennbar.",
                    evidence=f"Fields: {fields}",
                )
            )

    if not findings:
        findings.append(build_finding("F-CSRF-COVERAGE", target, "CSRF-Workflow-Pruefung abgeschlossen", "Info"))
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    payload = {"script": "24_csrf_workflows.py", "timestamp": now_iso(), "target": target, "findings": audit(target)}
    filename = write_script_output("24_csrf", payload)
    print(f"[+] {len(payload['findings'])} findings -> {filename}")
