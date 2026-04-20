"""Sucht nach Debug-, Stacktrace- und Fehlersignaturen, die Injections beguenstigen."""
from __future__ import annotations

import re
import sys

from auditlib import RateLimitedHttpClient, build_finding, default_target, load_inventory, now_iso, write_script_output

ERROR_PATTERNS = {
    "stacktrace": re.compile(r"(traceback|stack trace|exception:|fatal error)", re.IGNORECASE),
    "sql_error": re.compile(r"(sql syntax|sqlstate|database error|pdoexception|psqlexception)", re.IGNORECASE),
    "template_error": re.compile(r"(templateerror|jinja2|twig\\error|mustache)", re.IGNORECASE),
}


def audit(target: str) -> list[dict]:
    inventory = load_inventory()
    client = RateLimitedHttpClient()
    findings: list[dict] = []
    candidates = inventory.get("page_urls", [])[:20] + inventory.get("api_urls", [])[:20]

    for url in candidates:
        try:
            response = client.get(url, allow_redirects=True)
        except Exception:
            continue
        body = response.text[:120000]
        for label, pattern in ERROR_PATTERNS.items():
            if pattern.search(body):
                severity = "High" if label == "sql_error" else "Medium"
                findings.append(
                    build_finding(
                        f"F-INJECT-{label.upper()}-{abs(hash(url)) & 0xFFFF}",
                        url,
                        "Debug- oder Fehlerdetail offen sichtbar",
                        severity,
                        description="Die Antwort verraet interne Fehlerdetails, die Injections oder Missbrauch erleichtern.",
                        evidence=pattern.search(body).group(0),
                        cwe="CWE-209",
                    )
                )

    if not findings:
        findings.append(build_finding("F-INJECT-COVERAGE", target, "Injection-Signalpruefung abgeschlossen", "Info"))
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    payload = {"script": "27_injection_signals.py", "timestamp": now_iso(), "target": target, "findings": audit(target)}
    filename = write_script_output("27_injection", payload)
    print(f"[+] {len(payload['findings'])} findings -> {filename}")
