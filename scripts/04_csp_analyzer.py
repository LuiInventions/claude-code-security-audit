"""CSP-Parser mit Scoring. Erkennt unsafe-inline, unsafe-eval, wildcards, missing directives."""
import json
import pathlib
import sys
import time
from datetime import datetime, timezone

import requests
from auditlib import default_target, write_script_output

DANGEROUS_SOURCES = ["'unsafe-inline'", "'unsafe-eval'", "data:", "*", "http:", "https:"]
REQUIRED_DIRECTIVES = ["default-src", "script-src", "style-src", "object-src", "frame-ancestors", "base-uri"]


def parse_csp(csp_value):
    directives = {}
    for part in csp_value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        directives[tokens[0].lower()] = tokens[1:]
    return directives


def audit(url):
    findings = []
    try:
        response = requests.get(url, timeout=10)
    except Exception as exc:
        return [{"id": "F-CSP-ERR", "severity": "Info", "title": f"CSP-Scan failed: {exc}", "target": url}]

    csp = response.headers.get("Content-Security-Policy", "")
    if not csp:
        return [
            {
                "id": "F-CSP-MISSING",
                "target": url,
                "severity": "High",
                "title": "Content-Security-Policy fehlt komplett",
                "fix": "Strikte CSP setzen: `default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'`",
                "cwe": "CWE-1021",
                "owasp": "A05:2021",
            }
        ]

    directives = parse_csp(csp)
    for directive in REQUIRED_DIRECTIVES:
        if directive not in directives:
            findings.append(
                {
                    "id": f"F-CSP-MISS-{directive}",
                    "target": url,
                    "severity": "Low",
                    "title": f"CSP-Directive fehlt: {directive}",
                    "fix": f"`{directive}` in CSP ergänzen.",
                }
            )

    if "script-src" in directives:
        if "'unsafe-inline'" in directives["script-src"]:
            findings.append(
                {
                    "id": "F-CSP-UNSAFE-INLINE",
                    "target": url,
                    "severity": "Medium",
                    "title": "CSP erlaubt 'unsafe-inline' in script-src",
                    "description": "Macht CSP als XSS-Schutz nahezu wirkungslos.",
                    "fix": "Inline-Scripts in externe .js auslagern, Nonces oder Hashes verwenden.",
                    "cwe": "CWE-79",
                    "owasp": "A03:2021",
                }
            )
        if "'unsafe-eval'" in directives["script-src"]:
            findings.append(
                {
                    "id": "F-CSP-UNSAFE-EVAL",
                    "target": url,
                    "severity": "Medium",
                    "title": "CSP erlaubt 'unsafe-eval' in script-src",
                    "description": "`eval()`, `new Function()` und String-Timer werden erlaubt.",
                    "fix": "eval-Nutzung aus Code entfernen und Directive streichen.",
                    "cwe": "CWE-95",
                }
            )
        for source in directives["script-src"]:
            if source in ("*", "https:", "http:") or source.endswith(".*"):
                findings.append(
                    {
                        "id": "F-CSP-WILDCARD-SCRIPT",
                        "target": url,
                        "severity": "Medium",
                        "title": f"CSP script-src enthält gefährliche Wildcard: {source}",
                        "fix": "Nur konkrete Domains whitelisten.",
                    }
                )

    all_sources = sum((value for value in directives.values()), [])
    for source in all_sources:
        if source in ("https://unpkg.com", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"):
            findings.append(
                {
                    "id": f"F-CSP-CDN-{source.replace('https://', '').replace('.', '-')}",
                    "target": url,
                    "severity": "Low",
                    "title": f"CSP erlaubt CDN ohne SRI: {source}",
                    "description": "Ein kompromittiertes CDN-Paket wäre ohne SRI sofort ausführbar.",
                    "fix": "Entweder self-hosten oder Subresource Integrity (SRI) erzwingen.",
                    "cwe": "CWE-829",
                }
            )

    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    out = {
        "script": "04_csp_analyzer.py",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "findings": audit(target),
    }
    filename = write_script_output("04_csp", out)
    print(f"[+] {len(out['findings'])} findings -> {filename}")
