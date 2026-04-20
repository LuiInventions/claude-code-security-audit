"""Prueft Seiten auf harmlose, aber unmaskierte Reflection-Kontexte."""
from __future__ import annotations

import html
import re
import sys
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from auditlib import RateLimitedHttpClient, build_finding, default_target, load_inventory, now_iso, write_script_output

CANARY = "auditcanary_12345__<'\">"


def with_canary(url: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params["audit_ref"] = CANARY
    return urlunparse(parsed._replace(query=urlencode(params)))


def reflection_context(body: str) -> str:
    if CANARY in body:
        if re.search(rf"<script[^>]*>{re.escape(CANARY)}", body):
            return "script"
        if re.search(rf'=\s*["\']{re.escape(CANARY)}["\']', body):
            return "attribute"
        return "html"
    escaped = html.escape(CANARY)
    if escaped in body:
        return "escaped"
    return ""


def audit(target: str) -> list[dict]:
    inventory = load_inventory()
    client = RateLimitedHttpClient()
    findings: list[dict] = []

    for page_url in inventory.get("page_urls", [])[:20]:
        probe_url = with_canary(page_url)
        try:
            response = client.get(probe_url, allow_redirects=True)
        except Exception:
            continue
        if "html" not in response.headers.get("Content-Type", ""):
            continue
        context = reflection_context(response.text[:250000])
        if context in ("html", "attribute", "script"):
            severity = "Medium" if context in ("attribute", "script") else "Low"
            findings.append(
                build_finding(
                    f"F-REFLECT-{context.upper()}-{abs(hash(page_url)) & 0xFFFF}",
                    probe_url,
                    "Unsanitized Reflection erkannt",
                    severity,
                    description="Ein harmloser Canary-Wert wird ohne ausreichendes Escaping reflektiert.",
                    evidence=f"Kontext: {context}",
                    cwe="CWE-79",
                )
            )

    if not findings:
        findings.append(build_finding("F-REFLECT-COVERAGE", target, "Reflection-Probe ohne Treffer abgeschlossen", "Info"))
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    payload = {"script": "26_reflection_probe.py", "timestamp": now_iso(), "target": target, "findings": audit(target)}
    filename = write_script_output("26_reflect", payload)
    print(f"[+] {len(payload['findings'])} findings -> {filename}")
