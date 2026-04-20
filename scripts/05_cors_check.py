"""CORS-Probing: testet, ob ACAO reflected, wildcard oder null-origin-trust."""
import json
import pathlib
import sys
import time
from datetime import datetime, timezone

import requests
from auditlib import default_target, write_script_output

TEST_ORIGINS = [
    "https://evil.com",
    "null",
    "https://attacker.authorized-target.example.evil.com",
]


def audit(url, api_path="/api/contact"):
    findings = []
    for origin in TEST_ORIGINS:
        try:
            response = requests.options(
                url.rstrip("/") + api_path,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type",
                },
                timeout=10,
            )
            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                findings.append(
                    {
                        "id": "F-CORS-WILDCARD",
                        "target": url + api_path,
                        "severity": "Medium",
                        "title": "CORS: ACAO=* auf API-Endpoint",
                        "evidence": f"Origin: {origin} -> ACAO: *",
                        "fix": "ACAO auf konkrete Origin beschränken.",
                        "cwe": "CWE-942",
                    }
                )
            elif acao == origin and origin in ("https://evil.com", "null"):
                findings.append(
                    {
                        "id": "F-CORS-REFLECT",
                        "target": url + api_path,
                        "severity": "High",
                        "title": "CORS reflektiert beliebige Origins",
                        "evidence": f"Origin: {origin} -> ACAO: {acao}",
                        "fix": "Origin gegen Whitelist prüfen statt zu reflektieren.",
                        "cwe": "CWE-346",
                    }
                )
            if acac.lower() == "true" and (acao == "*" or "evil" in acao):
                findings.append(
                    {
                        "id": "F-CORS-CREDS",
                        "target": url + api_path,
                        "severity": "High",
                        "title": "CORS: Allow-Credentials + permissive Origin",
                        "evidence": f"ACAO: {acao}, ACAC: {acac}",
                        "fix": "Credentials nur bei strikter Origin-Whitelist erlauben.",
                    }
                )
        except Exception:
            continue
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    out = {
        "script": "05_cors_check.py",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "findings": audit(target),
    }
    filename = write_script_output("05_cors", out)
    print(f"[+] {len(out['findings'])} findings -> {filename}")
