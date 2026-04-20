"""Security-Header-Audit. Prüft Vorhandensein und Werte kritischer Response-Header."""
import json
import pathlib
import sys
import time
from datetime import datetime, timezone

import requests
from auditlib import default_target, write_script_output

REQUIRED = {
    "Strict-Transport-Security": {
        "severity": "High",
        "check": lambda v: "max-age=" in v and int(v.split("max-age=")[1].split(";")[0]) >= 15768000,
    },
    "Content-Security-Policy": {"severity": "High", "check": lambda v: v and "default-src" in v},
    "X-Frame-Options": {"severity": "Medium", "check": lambda v: v.upper() in ("DENY", "SAMEORIGIN")},
    "X-Content-Type-Options": {"severity": "Medium", "check": lambda v: v.lower() == "nosniff"},
    "Referrer-Policy": {
        "severity": "Low",
        "check": lambda v: v.lower() in ("no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"),
    },
    "Permissions-Policy": {"severity": "Low", "check": lambda v: bool(v)},
    "Cross-Origin-Opener-Policy": {
        "severity": "Low",
        "check": lambda v: v.lower() in ("same-origin", "same-origin-allow-popups"),
    },
}

DEPRECATED = [
    "X-XSS-Protection",
    "X-Download-Options",
    "X-Permitted-Cross-Domain-Policies",
    "Pragma",
    "Expires",
]


def audit(url):
    findings = []
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = {k.lower(): v for k, v in response.headers.items()}
    except Exception as exc:
        return [{"id": "F-HDR-ERR", "severity": "Info", "title": f"Header-Scan fehlgeschlagen: {exc}", "target": url}]

    for name, cfg in REQUIRED.items():
        value = headers.get(name.lower(), "")
        if not value:
            findings.append(
                {
                    "id": f"F-HDR-{name.upper().replace('-', '')}",
                    "target": url,
                    "title": f"Header fehlt: {name}",
                    "severity": cfg["severity"],
                    "description": f"Der Header `{name}` ist nicht gesetzt.",
                    "fix": f"In Caddyfile/Server-Config `{name}` mit passendem Wert setzen.",
                    "cwe": "CWE-693",
                    "owasp": "A05:2021",
                }
            )
        else:
            try:
                if not cfg["check"](value):
                    findings.append(
                        {
                            "id": f"F-HDR-{name.upper().replace('-', '')}-WEAK",
                            "target": url,
                            "title": f"Header schwach konfiguriert: {name}",
                            "severity": cfg["severity"],
                            "description": f"Wert: `{value}` erfüllt Best-Practice nicht.",
                            "evidence": value,
                            "cwe": "CWE-693",
                        }
                    )
            except Exception:
                pass

    for deprecated in DEPRECATED:
        if deprecated.lower() in headers:
            findings.append(
                {
                    "id": f"F-HDR-DEPRECATED-{deprecated.upper().replace('-', '')}",
                    "target": url,
                    "title": f"Deprecated Header gesetzt: {deprecated}",
                    "severity": "Info",
                    "description": f"`{deprecated}` ist veraltet und sollte entfernt werden.",
                    "fix": f"Header `{deprecated}` aus der Server-Config entfernen.",
                    "evidence": headers[deprecated.lower()],
                }
            )

    server = headers.get("server", "")
    if any(ch.isdigit() for ch in server):
        findings.append(
            {
                "id": "F-HDR-SERVER-LEAK",
                "target": url,
                "title": "Server-Header leakt Version",
                "severity": "Low",
                "evidence": server,
                "description": "Server-Header enthält Versionsinfo und erleichtert gezielte Exploits.",
                "fix": "Server-Signatur minimieren (z.B. in Caddy: `header -Server`).",
                "cwe": "CWE-200",
            }
        )

    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    out = {
        "script": "01_headers.py",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "findings": audit(target),
    }
    filename = write_script_output("01_headers", out)
    print(f"[+] {len(out['findings'])} findings -> {filename}")
