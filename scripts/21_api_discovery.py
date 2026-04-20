"""Prueft automatisch erkannte API-Endpunkte und oeffentliche API-Dokumentation."""
from __future__ import annotations

import sys
from urllib.parse import urlparse

from auditlib import RateLimitedHttpClient, build_finding, default_target, load_inventory, now_iso, write_script_output


def audit(target: str) -> list[dict]:
    inventory = load_inventory()
    client = RateLimitedHttpClient()
    findings: list[dict] = []
    api_urls = inventory.get("api_urls", [])[:40]

    for api_url in api_urls:
        try:
            response = client.get(api_url, allow_redirects=True)
        except Exception:
            continue
        content_type = response.headers.get("Content-Type", "")
        body = response.text[:5000].lower()
        path = urlparse(api_url).path.lower()
        looks_like_api_docs = (
            "application/json" in content_type
            or "application/yaml" in content_type
            or "openapi" in body
            or "swagger" in body
        )
        if response.status_code == 200 and any(token in path for token in ("openapi", "swagger")) and looks_like_api_docs:
            findings.append(
                build_finding(
                    f"F-API-DOCS-{abs(hash(api_url)) & 0xFFFF}",
                    api_url,
                    "Oeffentliche API-Dokumentation erreichbar",
                    "Low",
                    description="OpenAPI-/Swagger-Endpunkt ist ohne Authentifizierung erreichbar.",
                    evidence=f"Status {response.status_code}, Content-Type: {content_type}",
                    cwe="CWE-200",
                )
            )
        if response.status_code == 200 and "application/json" in content_type and any(token in path for token in ("admin", "internal", "debug")):
            findings.append(
                build_finding(
                    f"F-API-INTERNAL-{abs(hash(api_url)) & 0xFFFF}",
                    api_url,
                    "Potenziell interner API-Endpunkt oeffentlich erreichbar",
                    "High",
                    description="Ein intern wirkender API-Pfad antwortet anonym mit JSON.",
                    evidence=f"Status {response.status_code}, Path: {path}",
                    cwe="CWE-284",
                )
            )
        if path.endswith("/graphql") or "graphql" in path:
            try:
                probe = client.post(api_url, json={"query": "{__typename}"})
            except Exception:
                continue
            if probe.status_code == 200 and probe.headers.get("Content-Type", "").startswith("application/json") and "data" in probe.text:
                findings.append(
                    build_finding(
                        f"F-API-GRAPHQL-{abs(hash(api_url)) & 0xFFFF}",
                        api_url,
                        "GraphQL-Endpoint nimmt anonyme Queries an",
                        "Info",
                        description="Die GraphQL-Oberflaeche ist erreichbar und sollte bewusst abgesichert sein.",
                        evidence=probe.text[:200],
                    )
                )

    if not findings:
        findings.append(
            build_finding(
                "F-API-COVERAGE",
                target,
                "API-Discovery abgeschlossen",
                "Info",
                description=f"{len(api_urls)} API-Kandidaten wurden ohne kritischen Befund geprueft.",
            )
        )
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    payload = {"script": "21_api_discovery.py", "timestamp": now_iso(), "target": target, "findings": audit(target)}
    filename = write_script_output("21_api", payload)
    print(f"[+] {len(payload['findings'])} findings -> {filename}")
