"""Analysiert JS-Bundles, Source Maps und Konfigurationsleaks."""
from __future__ import annotations

import re
import sys

from auditlib import RateLimitedHttpClient, build_finding, default_target, load_inventory, now_iso, redact_text, write_script_output

SECRET_PATTERNS = {
    "generic_secret": re.compile(r"(?i)(api[_-]?key|secret|token)[\"'\s:=]{1,8}([A-Za-z0-9_\-]{10,})"),
    "aws_key": re.compile(r"(AKIA[0-9A-Z]{16})"),
    "private_host": re.compile(r"(https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[^\"' ]*)"),
}


def audit(target: str) -> list[dict]:
    inventory = load_inventory()
    client = RateLimitedHttpClient()
    findings: list[dict] = []
    assets = [url for url in inventory.get("asset_urls", []) if url.lower().endswith((".js", ".map"))][:25]

    for asset_url in assets:
        try:
            response = client.get(asset_url, allow_redirects=True)
        except Exception:
            continue
        body = response.text[:400000]
        for label, pattern in SECRET_PATTERNS.items():
            match = pattern.search(body)
            if match:
                findings.append(
                    build_finding(
                        f"F-BUNDLE-{label.upper()}-{abs(hash(asset_url)) & 0xFFFF}",
                        asset_url,
                        "Verdacht auf Secret- oder internes Infrastruktur-Leak im Bundle",
                        "High" if label != "private_host" else "Medium",
                        description="Frontend-Asset enthaelt ein verdachtsbehaftetes Secret- oder Infrastruktur-Muster.",
                        evidence=redact_text(match.group(0)),
                        cwe="CWE-798" if label != "private_host" else "CWE-200",
                    )
                )
        if "sourceMappingURL=" in body:
            findings.append(
                build_finding(
                    f"F-BUNDLE-SOURCEMAP-{abs(hash(asset_url)) & 0xFFFF}",
                    asset_url,
                    "JS-Bundle verweist auf Source Map",
                    "Low",
                    description="Source Maps koennen Quellstruktur, interne Kommentare und Build-Details offenlegen.",
                    evidence="sourceMappingURL gefunden",
                    cwe="CWE-200",
                )
            )

    if not findings:
        findings.append(build_finding("F-BUNDLE-COVERAGE", target, "Bundle- und Secret-Pruefung abgeschlossen", "Info"))
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    payload = {"script": "28_bundle_secrets.py", "timestamp": now_iso(), "target": target, "findings": audit(target)}
    filename = write_script_output("28_bundle", payload)
    print(f"[+] {len(payload['findings'])} findings -> {filename}")
