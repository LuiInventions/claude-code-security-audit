"""Prueft Upload- und Download-Flaechen auf offensichtliche Schwachpunkte."""
from __future__ import annotations

import sys

from auditlib import RateLimitedHttpClient, build_finding, default_target, load_inventory, now_iso, write_script_output


def audit(target: str) -> list[dict]:
    inventory = load_inventory()
    client = RateLimitedHttpClient()
    findings: list[dict] = []

    for form in inventory.get("forms", []):
        action = form.get("action", "")
        if form.get("file_inputs"):
            if not form.get("has_csrf_token"):
                findings.append(
                    build_finding(
                        f"F-UPLOAD-NOCSRF-{abs(hash(action)) & 0xFFFF}",
                        action,
                        "Upload-Formular ohne erkennbaren CSRF-Schutz",
                        "High",
                        description="Datei-Uploads sollten gegen Cross-Site-Missbrauch zusaetzlich abgesichert sein.",
                        evidence=f"File-Inputs: {form.get('file_inputs')}",
                        cwe="CWE-352",
                    )
                )

    for download_url in sorted(set(inventory.get("download_urls", [])))[:20]:
        try:
            response = client.get(download_url, allow_redirects=False)
        except Exception:
            continue
        content_disposition = response.headers.get("Content-Disposition", "")
        if response.status_code == 200 and (content_disposition or "application/" in response.headers.get("Content-Type", "")):
            findings.append(
                build_finding(
                    f"F-DOWNLOAD-PUBLIC-{abs(hash(download_url)) & 0xFFFF}",
                    download_url,
                    "Download-Endpunkt anonym erreichbar",
                    "Medium",
                    description="Download- oder Export-Endpunkt liefert bereits anonym eine Datei oder Binärantwort.",
                    evidence=f"Status {response.status_code}, Content-Disposition: {content_disposition or '[nicht gesetzt]'}",
                    cwe="CWE-200",
                )
            )

    if not findings:
        findings.append(build_finding("F-UPDOWN-COVERAGE", target, "Upload-/Download-Flaechen geprueft", "Info"))
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    payload = {"script": "25_upload_download.py", "timestamp": now_iso(), "target": target, "findings": audit(target)}
    filename = write_script_output("25_updown", payload)
    print(f"[+] {len(payload['findings'])} findings -> {filename}")
