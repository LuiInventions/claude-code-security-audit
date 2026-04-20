"""Sucht read-only nach Hinweisen auf fehlende Objekt-Autorisierung."""
from __future__ import annotations

import re
import sys
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from auditlib import RateLimitedHttpClient, build_finding, default_target, load_inventory, now_iso, write_script_output

SUSPECT_KEYWORDS = ("user", "users", "account", "order", "invoice", "document", "file", "customer", "profile", "api")


def mutate_identifier(url: str) -> str | None:
    parsed = urlparse(url)
    path = parsed.path
    match = re.search(r"(\d+)(?!.*\d)", path)
    if match:
        mutated = path[: match.start()] + str(int(match.group(1)) + 1) + path[match.end() :]
        return urlunparse(parsed._replace(path=mutated))
    query = parse_qs(parsed.query)
    for key in ("id", "user", "account", "file", "document"):
        if key in query and query[key] and query[key][0].isdigit():
            updated = dict(query)
            updated[key] = [str(int(query[key][0]) + 1)]
            return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
    return None


def audit(target: str) -> list[dict]:
    inventory = load_inventory()
    client = RateLimitedHttpClient()
    findings: list[dict] = []
    candidates = []
    for url in inventory.get("api_urls", []) + inventory.get("download_urls", []) + inventory.get("page_urls", []):
        lower = url.lower()
        if any(keyword in lower for keyword in SUSPECT_KEYWORDS):
            candidates.append(url)
    seen = set()
    for url in candidates[:30]:
        alternate = mutate_identifier(url)
        if not alternate or alternate in seen:
            continue
        seen.add(alternate)
        try:
            baseline = client.get(url, allow_redirects=False)
            variant = client.get(alternate, allow_redirects=False)
        except Exception:
            continue
        if baseline.status_code == 200 and variant.status_code == 200:
            if abs(len(baseline.text) - len(variant.text)) > 25:
                findings.append(
                    build_finding(
                        f"F-IDOR-POTENTIAL-{abs(hash(url)) & 0xFFFF}",
                        alternate,
                        "Potenziell fehlende Objekt-Autorisierung",
                        "High",
                        description="Zwei benachbarte Objekt-IDs liefern anonym unterschiedliche erfolgreiche Antworten.",
                        evidence=f"Basis {url} ({len(baseline.text)} bytes) vs. Variante {alternate} ({len(variant.text)} bytes)",
                        cwe="CWE-639",
                        owasp="A01:2021",
                    )
                )

    if not findings:
        findings.append(build_finding("F-IDOR-COVERAGE", target, "IDOR-Heuristik ohne Treffer abgeschlossen", "Info"))
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    payload = {"script": "23_authz_idor.py", "timestamp": now_iso(), "target": target, "findings": audit(target)}
    filename = write_script_output("23_authz", payload)
    print(f"[+] {len(payload['findings'])} findings -> {filename}")
