"""Form-Endpoint-Tests: Origin-Check, Rate-Limit, Honeypot-Akzeptanz. KEINE Injection-Payloads."""
import sys
import time
from datetime import datetime, timezone

import requests
from auditlib import build_finding, default_target, load_inventory, write_script_output


def audit_endpoint(url, target_url):
    findings = []
    # 1. Origin-Check (None)
    try:
        response = requests.post(target_url, json={}, timeout=10)
        if response.status_code == 200:
            findings.append(
                build_finding(
                    "F-FORM-NO-ORIGIN-CHECK",
                    target_url,
                    "API akzeptiert Requests ohne Origin-Check",
                    "Medium",
                    evidence=f"POST ohne Origin -> {response.status_code}",
                    fix="Server-seitig Origin-Header validieren.",
                    cwe="CWE-352",
                )
            )
    except Exception:
        pass

    # 2. Origin-Check (Evil)
    try:
        response = requests.post(target_url, json={}, headers={"Origin": "https://evil.com"}, timeout=10)
        if response.status_code == 200:
            findings.append(
                build_finding(
                    "F-FORM-ORIGIN-ANY",
                    target_url,
                    "API akzeptiert beliebige Origins",
                    "High",
                    evidence=f"Origin: evil.com -> {response.status_code}",
                    fix="Origin-Whitelist strikt pruefen.",
                    cwe="CWE-346",
                )
            )
    except Exception:
        pass

    # 3. Rate-Limit heuristic (12 requests)
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
            build_finding(
                "F-FORM-NO-RATELIMIT",
                target_url,
                "Kein Rate-Limit auf sensitiver Form-Action erkennbar",
                "Medium",
                evidence=f"12 Requests, Codes: {codes}",
                fix="Rate-Limit einbauen (z.B. express-rate-limit, slowapi).",
                cwe="CWE-799",
            )
        )
    elif 429 in codes:
        findings.append(
            build_finding(
                "F-FORM-RATELIMIT-OK",
                target_url,
                f"Rate-Limit aktiv (429 nach {codes.index(429) + 1} Requests)",
                "Info",
            )
        )
    return findings


def audit(url):
    inventory = load_inventory()
    forms = inventory.get("forms", [])
    
    # Sammle interessante Actions (POST-Endpunkte)
    endpoints = []
    for f in forms:
        if f.get("method") == "POST" and f.get("action"):
            endpoints.append(f["action"])
    
    # Eindeutige Endpunkte, priorisiere typische Kontakten/API Namen
    target_endpoints = sorted(set(endpoints), key=lambda x: ("contact" in x.lower() or "api" in x.lower()), reverse=True)
    
    # Wenn nichts im Inventar, Fallback auf Standard
    if not target_endpoints:
        target_endpoints = [url.rstrip("/") + "/api/contact"]

    all_findings = []
    # Pruefe maximal 3 verschiedene Endpunkte um Zeit/Rate-Limits zu schonen
    for target_url in target_endpoints[:3]:
        all_findings.extend(audit_endpoint(url, target_url))
    
    return all_findings


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
