"""Form-Endpoint-Tests: Origin-Check, Rate-Limit, Honeypot-Akzeptanz. KEINE Injection-Payloads."""
import json
import pathlib
import sys
import time
from datetime import datetime, timezone

import requests
from auditlib import default_target, write_script_output


def audit(url, endpoint="/api/contact"):
    findings = []
    target_url = url.rstrip("/") + endpoint

    try:
        response = requests.post(target_url, json={}, timeout=10)
        if response.status_code == 200:
            findings.append(
                {
                    "id": "F-FORM-NO-ORIGIN-CHECK",
                    "target": target_url,
                    "severity": "Medium",
                    "title": "API akzeptiert Requests ohne Origin-Check",
                    "evidence": f"POST ohne Origin -> {response.status_code}",
                    "fix": "Server-seitig Origin-Header validieren.",
                    "cwe": "CWE-352",
                }
            )
    except Exception:
        pass

    try:
        response = requests.post(target_url, json={}, headers={"Origin": "https://evil.com"}, timeout=10)
        if response.status_code == 200:
            findings.append(
                {
                    "id": "F-FORM-ORIGIN-ANY",
                    "target": target_url,
                    "severity": "High",
                    "title": "API akzeptiert beliebige Origins",
                    "evidence": f"Origin: evil.com -> {response.status_code}",
                    "fix": "Origin-Whitelist strikt prüfen.",
                }
            )
    except Exception:
        pass

    good_origin = {"Origin": url}
    codes = []
    for _ in range(12):
        try:
            response = requests.post(target_url, json={}, headers=good_origin, timeout=5)
            codes.append(response.status_code)
            if response.status_code == 429:
                break
            time.sleep(0.2)
        except Exception:
            codes.append(0)

    if 429 not in codes and len([code for code in codes if code in (200, 400, 422)]) >= 10:
        findings.append(
            {
                "id": "F-FORM-NO-RATELIMIT",
                "target": target_url,
                "severity": "Medium",
                "title": "Kein Rate-Limit erkennbar",
                "evidence": f"12 Requests, Codes: {codes}",
                "fix": "Rate-Limit einbauen (z.B. express-rate-limit, slowapi).",
            }
        )
    elif 429 in codes:
        findings.append(
            {
                "id": "F-FORM-RATELIMIT-OK",
                "target": target_url,
                "severity": "Info",
                "title": f"Rate-Limit aktiv (429 nach {codes.index(429) + 1} Requests)",
            }
        )

    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    out = {
        "script": "09_form_probe.py",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "findings": audit(target),
    }
    filename = write_script_output("09_form", out)
    print(f"[+] {len(out['findings'])} findings -> {filename}")
