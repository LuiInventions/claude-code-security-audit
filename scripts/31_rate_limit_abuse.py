"""Prueft sensible Endpunkte auf fehlendes oder schwaches Rate-Limiting."""
from __future__ import annotations

import sys
import time

from auditlib import RateLimitedHttpClient, build_finding, default_target, load_inventory, now_iso, write_script_output


def audit(target: str) -> list[dict]:
    inventory = load_inventory()
    client = RateLimitedHttpClient()
    findings: list[dict] = []
    auth_form_actions = [
        form.get("action", "")
        for form in inventory.get("forms", [])
        if form.get("has_password") or form.get("file_inputs") or form.get("method") in ("POST", "PUT", "PATCH", "DELETE")
    ]
    candidates = sorted(
        set(
            inventory.get("api_urls", [])
            + inventory.get("upload_urls", [])
            + inventory.get("mutating_endpoints", [])
            + auth_form_actions
        )
    )[:12]

    for url in candidates:
        try:
            baseline = client.get(url, allow_redirects=False)
        except Exception:
            continue
        content_type = baseline.headers.get("Content-Type", "")
        if "html" in content_type and not any(token in url.lower() for token in ("/api/", "/graphql", "login", "register", "password", "upload")):
            continue
        codes = []
        for _ in range(8):
            try:
                response = client.get(url, allow_redirects=False)
            except Exception:
                codes.append(0)
                continue
            codes.append(response.status_code)
            if response.status_code == 429:
                break
            time.sleep(0.25)
        accepted = [code for code in codes if code in (200, 204, 400, 401, 403, 405, 422)]
        if 429 not in codes and len(accepted) >= 6:
            findings.append(
                build_finding(
                    f"F-RATELIMIT-WEAK-{abs(hash(url)) & 0xFFFF}",
                    url,
                    "Kein fruehes Rate-Limit auf sensiblem Endpoint erkennbar",
                    "Medium",
                    description="Mehrere schnelle Requests wurden ohne erkennbare Drosselung beantwortet.",
                    evidence=f"Antwortcodes: {codes}",
                    cwe="CWE-770",
                )
            )

    if not findings:
        findings.append(build_finding("F-RATELIMIT-COVERAGE", target, "Rate-Limit-Pruefung abgeschlossen", "Info"))
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    payload = {"script": "31_rate_limit_abuse.py", "timestamp": now_iso(), "target": target, "findings": audit(target)}
    filename = write_script_output("31_ratelimit", payload)
    print(f"[+] {len(payload['findings'])} findings -> {filename}")
