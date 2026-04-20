"""Probes für typische exposed files. Baut SPA-Fallback-Detection ein."""
import json
import pathlib
import sys
import time
from datetime import datetime, timezone

import requests
from auditlib import default_target, write_script_output

PATHS = [
    ".git/config",
    ".git/HEAD",
    ".env",
    ".env.local",
    ".env.production",
    "backup.zip",
    "backup.tar.gz",
    "dump.sql",
    "sitemap.xml",
    "robots.txt",
    ".well-known/security.txt",
    "admin",
    "admin/",
    "wp-admin",
    "wp-login.php",
    "phpmyadmin",
    ".htaccess",
    ".htpasswd",
    ".DS_Store",
    "Thumbs.db",
    "config.json",
    "config.yml",
    "config.php",
    "composer.json",
    "package.json",
    "docker-compose.yml",
    "Caddyfile",
    "server-status",
    "server-info",
    "phpinfo.php",
    "info.php",
    "debug",
    "test.php",
    "test/",
    "dev/",
    "staging/",
    "api/debug",
    "api/admin",
    "api/v1/admin",
    "CHANGELOG.md",
    "README.md",
    ".vscode/settings.json",
    ".idea/workspace.xml",
]


def audit(url):
    findings = []
    base = url.rstrip("/")
    try:
        baseline = requests.get(base + "/", timeout=10)
        baseline_len = len(baseline.content)
    except Exception as exc:
        return [{"id": "F-EXP-ERR", "severity": "Info", "title": f"Exposed-Scan failed: {exc}", "target": url}]

    random_path = f"/_nonexistent_check_{int(time.time())}_xyz"
    try:
        negative = requests.get(base + random_path, timeout=10)
        neg_len = len(negative.content)
        neg_status = negative.status_code
    except Exception:
        neg_len, neg_status = 0, 404

    spa_fallback = neg_status == 200 and neg_len == baseline_len
    if spa_fallback:
        findings.append(
            {
                "id": "F-EXP-SPAFALLBACK",
                "target": url,
                "title": "SPA-Fallback liefert 200 für alle Pfade",
                "severity": "Low",
                "description": "Jeder nicht existierende Pfad liefert die index.html. Erschwert echte Fehler-Erkennung, SEO und UX.",
                "fix": "In Caddyfile `try_files` ohne `/index.html`-Fallback konfigurieren, stattdessen `=404`.",
                "evidence": f"GET {random_path} -> {neg_status}, {neg_len} bytes",
            }
        )

    for path in PATHS:
        try:
            response = requests.get(f"{base}/{path}", timeout=10, allow_redirects=False)
            status = response.status_code
            content_length = len(response.content)
            content_type = response.headers.get("Content-Type", "")
            is_spa = spa_fallback and status == 200 and content_length == baseline_len
            is_real_hit = status == 200 and not is_spa
            if is_real_hit:
                findings.append(
                    {
                        "id": f"F-EXP-HIT-{path.replace('/', '_').replace('.', '_')}",
                        "target": f"{base}/{path}",
                        "title": f"Exposed: {path}",
                        "severity": "High",
                        "description": f"Pfad `{path}` liefert 200 mit eigenem Inhalt (nicht SPA-Fallback).",
                        "evidence": f"Status {status}, {content_length} bytes, Content-Type: {content_type}",
                        "fix": "Pfad aus öffentlichem Verzeichnis entfernen oder Zugriff blockieren.",
                        "cwe": "CWE-538",
                        "owasp": "A01:2021",
                    }
                )
            elif status == 403:
                findings.append(
                    {
                        "id": f"F-EXP-403-{path.replace('/', '_').replace('.', '_')}",
                        "target": f"{base}/{path}",
                        "title": f"Pfad existiert aber geblockt: {path}",
                        "severity": "Info",
                        "description": "403 signalisiert Existenz und erleichtert Recon.",
                    }
                )
        except Exception:
            continue

    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    out = {
        "script": "02_exposed_files.py",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "findings": audit(target),
    }
    filename = write_script_output("02_exposed", out)
    print(f"[+] {len(out['findings'])} findings -> {filename}")
