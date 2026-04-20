"""Wrapper um katana. Schreibt alle gefundenen URLs nach findings/urls.txt."""
import json
import pathlib
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from auditlib import artifact_path, default_target, repo_root, write_script_output


def audit(url):
    findings = []
    local_katana = repo_root() / "tools" / "katana.exe"
    katana = shutil.which("katana") or str(local_katana)
    if not pathlib.Path(katana).exists() and not shutil.which("katana"):
        return [
            {
                "id": "F-CRAWL-MISSING",
                "severity": "Info",
                "target": url,
                "title": "katana nicht installiert — Fallback nicht verfügbar",
                "fix": "katana von github.com/projectdiscovery/katana/releases installieren",
            }
        ]

    out_file = artifact_path(f"urls_{int(time.time())}.txt")
    cmd = [katana, "-u", url, "-d", "3", "-c", "5", "-silent", "-o", str(out_file), "-fs", "rdn"]
    try:
        subprocess.run(cmd, timeout=120, check=False)
        if out_file.exists():
            urls = out_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            findings.append(
                {
                    "id": "F-CRAWL-OK",
                    "severity": "Info",
                    "target": url,
                    "title": f"Crawler fand {len(urls)} URLs",
                    "evidence": f"Siehe {out_file}",
                }
            )
    except subprocess.TimeoutExpired:
        findings.append(
            {"id": "F-CRAWL-TIMEOUT", "severity": "Info", "target": url, "title": "Crawler-Timeout nach 120 Sekunden"}
        )
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    out = {
        "script": "11_crawler.py",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "findings": audit(target),
    }
    filename = write_script_output("11_crawl", out)
    print(f"[+] crawl done -> {filename}")
