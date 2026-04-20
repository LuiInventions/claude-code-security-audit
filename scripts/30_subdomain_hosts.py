"""Sammelt und prueft erreichbare Subdomains und Host-Varianten."""
from __future__ import annotations

import socket
import sys

from auditlib import (
    RateLimitedHttpClient,
    build_finding,
    default_target,
    load_inventory,
    now_iso,
    registrable_domain,
    write_script_output,
)

COMMON_SUBDOMAINS = ["www", "api", "admin", "app", "portal", "static", "cdn", "staging", "dev"]


def resolvable(hostname: str) -> bool:
    try:
        socket.getaddrinfo(hostname, 443)
        return True
    except Exception:
        return False


def audit(target: str) -> list[dict]:
    inventory = load_inventory()
    client = RateLimitedHttpClient()
    findings: list[dict] = []
    base_hosts = inventory.get("hosts", [])
    if not base_hosts:
        return [build_finding("F-HOSTS-NOINVENTORY", target, "Keine Hosts im Inventory fuer Host-Coverage", "Info")]
    domain = registrable_domain(base_hosts[0].split(":")[0])
    candidates = set(base_hosts)
    for prefix in COMMON_SUBDOMAINS:
        candidates.add(f"{prefix}.{domain}")

    for hostname in sorted(candidates):
        if ":" in hostname or not resolvable(hostname):
            continue
        url = f"https://{hostname}/"
        try:
            response = client.get(url, allow_redirects=True)
        except Exception:
            continue
        if any(label in hostname for label in ("staging", "dev", "admin")) and response.status_code < 500:
            findings.append(
                build_finding(
                    f"F-HOSTS-SENSITIVE-{abs(hash(hostname)) & 0xFFFF}",
                    url,
                    "Sensible Subdomain oeffentlich erreichbar",
                    "High",
                    description="Eine potenziell nicht fuer die Oeffentlichkeit gedachte Host-Variante antwortet im Internet.",
                    evidence=f"Status {response.status_code}",
                    cwe="CWE-200",
                )
            )
        if "Strict-Transport-Security" not in response.headers:
            findings.append(
                build_finding(
                    f"F-HOSTS-NOHSTS-{abs(hash(hostname)) & 0xFFFF}",
                    url,
                    "Host ohne HSTS",
                    "Medium",
                    description="Nicht alle erreichbaren Hosts liefern dieselbe Transporthaertung.",
                    cwe="CWE-319",
                )
            )

    if not findings:
        findings.append(build_finding("F-HOSTS-COVERAGE", target, "Subdomain-/Host-Coverage abgeschlossen", "Info"))
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    payload = {"script": "30_subdomain_hosts.py", "timestamp": now_iso(), "target": target, "findings": audit(target)}
    filename = write_script_output("30_hosts", payload)
    print(f"[+] {len(payload['findings'])} findings -> {filename}")
