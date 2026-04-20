"""HTTP-Method-Enumeration. Sucht nach TRACE, PUT, DELETE, CONNECT."""
import json
import pathlib
import sys
import time
from datetime import datetime, timezone

import requests
from auditlib import default_target, write_script_output

METHODS = ["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH", "CONNECT"]


def audit(url):
    findings = []
    try:
        requests.options(url, timeout=10)
    except Exception as exc:
        return [{"id": "F-METHOD-ERR", "severity": "Info", "title": str(exc), "target": url}]

    for method in METHODS:
        try:
            response = requests.request(method, url, timeout=10)
            if response.status_code not in (405, 501, 400, 404):
                severity = "High" if method in ("PUT", "DELETE", "TRACE") else "Low"
                findings.append(
                    {
                        "id": f"F-METHOD-{method}",
                        "target": url,
                        "severity": severity,
                        "title": f"HTTP {method} erlaubt (Status {response.status_code})",
                        "fix": f"Nicht benötigte Methoden auf Server-Ebene blockieren. {method} sollte nur bei gezielter Nutzung erlaubt sein.",
                        "cwe": "CWE-650" if method == "TRACE" else "CWE-749",
                    }
                )
        except Exception:
            continue
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    out = {
        "script": "10_http_methods.py",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "findings": audit(target),
    }
    filename = write_script_output("10_methods", out)
    print(f"[+] {len(out['findings'])} findings -> {filename}")
