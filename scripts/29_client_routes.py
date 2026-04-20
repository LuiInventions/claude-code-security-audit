"""Prueft Client-Routen, Service Worker und Header-Konsistenz ueber mehrere Seiten."""
from __future__ import annotations

import sys
from bs4 import BeautifulSoup

from auditlib import RateLimitedHttpClient, build_finding, default_target, load_inventory, now_iso, normalize_url, write_script_output


def audit(target: str) -> list[dict]:
    inventory = load_inventory()
    client = RateLimitedHttpClient()
    findings: list[dict] = []
    pages = inventory.get("page_urls", [])[:20]
    header_snapshots = []

    for page_url in pages:
        try:
            response = client.get(page_url, allow_redirects=True)
        except Exception:
            continue
        if "html" not in response.headers.get("Content-Type", ""):
            continue
        body = response.text[:120000]
        headers = response.headers
        header_snapshots.append((page_url, headers))
        soup = BeautifulSoup(body, "html.parser")
        external_http_assets = []
        for tag in soup.find_all(src=True):
            src = tag.get("src", "")
            if src.startswith("http://"):
                external_http_assets.append(src)
        for tag in soup.find_all(href=True):
            href = tag.get("href", "")
            if href.startswith("http://") and any(href.lower().endswith(ext) for ext in (".css", ".js", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2")):
                external_http_assets.append(href)
        if external_http_assets and "https://" in target:
            findings.append(
                build_finding(
                    f"F-CLIENT-MIXED-{abs(hash(page_url)) & 0xFFFF}",
                    page_url,
                    "Hinweis auf Mixed-Content-Risiko",
                    "Medium",
                    description="Die Route referenziert absolute HTTP-Ressourcen trotz HTTPS-Ziel.",
                    evidence=external_http_assets[0],
                    cwe="CWE-319",
                )
            )

    if header_snapshots:
        baseline_url, baseline_headers = header_snapshots[0]
        baseline_csp = baseline_headers.get("Content-Security-Policy", "")
        for page_url, headers in header_snapshots[1:]:
            if bool(baseline_csp) != bool(headers.get("Content-Security-Policy", "")):
                findings.append(
                    build_finding(
                        f"F-CLIENT-HEADER-DRIFT-{abs(hash(page_url)) & 0xFFFF}",
                        page_url,
                        "Uneinheitliche Security-Header ueber Client-Routen",
                        "Medium",
                        description="Nicht alle geprueften Routen liefern dieselbe Security-Header-Haertung.",
                        evidence=f"Baseline: {baseline_url}",
                        cwe="CWE-693",
                    )
                )

    for special_path in ("/service-worker.js", "/manifest.json", "/manifest.webmanifest"):
        url = normalize_url(special_path, base_url=target)
        try:
            response = client.get(url, allow_redirects=True)
        except Exception:
            continue
        content_type = response.headers.get("Content-Type", "")
        if response.status_code == 200 and ("javascript" in content_type or "json" in content_type or "manifest" in content_type):
            findings.append(
                build_finding(
                    f"F-CLIENT-SPECIAL-{abs(hash(url)) & 0xFFFF}",
                    url,
                    "Client-Spezialressource oeffentlich erreichbar",
                    "Info",
                    description="Service Worker oder Manifest ist vorhanden und sollte bewusst gehaertet sein.",
                    evidence=f"Status {response.status_code}",
                )
            )

    if not findings:
        findings.append(build_finding("F-CLIENT-COVERAGE", target, "Client-Routen-Pruefung abgeschlossen", "Info"))
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    payload = {"script": "29_client_routes.py", "timestamp": now_iso(), "target": target, "findings": audit(target)}
    filename = write_script_output("29_client", payload)
    print(f"[+] {len(payload['findings'])} findings -> {filename}")
