"""Prueft Login-, Logout- und Passwort-Workflows auf sichtbare Schutzluecken."""
from __future__ import annotations

import sys
from urllib.parse import urlparse

from auditlib import RateLimitedHttpClient, build_finding, default_target, load_inventory, now_iso, write_script_output


def audit(target: str) -> list[dict]:
    inventory = load_inventory()
    client = RateLimitedHttpClient()
    findings: list[dict] = []
    auth_urls = sorted(set(inventory.get("auth_urls", [])))[:25]
    forms = inventory.get("forms", [])

    for form in forms:
        action = form.get("action", "")
        page = form.get("page", "")
        if not form.get("has_password"):
            continue
        if form.get("method") == "GET":
            findings.append(
                build_finding(
                    f"F-AUTH-GET-{abs(hash(action)) & 0xFFFF}",
                    action,
                    "Authentifizierungsformular nutzt GET",
                    "High",
                    description="Passwort- oder Login-Formulare sollten keine sensitiven Daten per GET uebertragen.",
                    evidence=f"Seite: {page}",
                    cwe="CWE-598",
                )
            )
        if not form.get("has_csrf_token"):
            findings.append(
                build_finding(
                    f"F-AUTH-NOCSRF-{abs(hash(action)) & 0xFFFF}",
                    action,
                    "Authentifizierungsformular ohne erkennbares CSRF-Token",
                    "Medium",
                    description="Auf Login-, Register- oder Passwort-Formularen fehlt ein erkennbarer CSRF-Schutz.",
                    evidence=f"Fields: {form.get('fields', [])}",
                    cwe="CWE-352",
                )
            )

    for auth_url in auth_urls:
        path = urlparse(auth_url).path.lower()
        try:
            response = client.get(auth_url, allow_redirects=True)
        except Exception:
            continue
        cache_control = response.headers.get("Cache-Control", "")
        if any(token in path for token in ("login", "signin", "reset", "password")) and "no-store" not in cache_control.lower():
            findings.append(
                build_finding(
                    f"F-AUTH-CACHE-{abs(hash(auth_url)) & 0xFFFF}",
                    auth_url,
                    "Auth-Seite ohne strikten Cache-Control",
                    "Low",
                    description="Login- oder Passwort-Seiten sollten nicht durch Browser-/Proxy-Caches persistiert werden.",
                    evidence=f"Cache-Control: {cache_control or '[nicht gesetzt]'}",
                    cwe="CWE-524",
                )
            )
        if "logout" in path and response.status_code in (200, 302, 303):
            findings.append(
                build_finding(
                    f"F-AUTH-LOGOUT-GET-{abs(hash(auth_url)) & 0xFFFF}",
                    auth_url,
                    "Logout ueber GET erreichbar",
                    "Medium",
                    description="GET-basierte Logout-Routen sind leichter fuer Cross-Site-Aktionen missbrauchbar.",
                    evidence=f"Status {response.status_code}",
                    cwe="CWE-352",
                )
            )

    if not findings:
        findings.append(build_finding("F-AUTH-COVERAGE", target, "Auth-Surface geprueft", "Info"))
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    payload = {"script": "22_auth_surface.py", "timestamp": now_iso(), "target": target, "findings": audit(target)}
    filename = write_script_output("22_auth", payload)
    print(f"[+] {len(payload['findings'])} findings -> {filename}")
