"""robots.txt + sitemap.xml analyse — findet Disallow-Pfade und Sitemap-URLs."""
import json
import pathlib
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import requests
from auditlib import default_target, write_script_output, write_text_artifact


def audit(url):
    findings, discovered = [], []
    base = url.rstrip("/")

    try:
        response = requests.get(base + "/robots.txt", timeout=10)
        if response.status_code == 200 and "text" in response.headers.get("Content-Type", ""):
            disallow_paths = [
                line.split(":", 1)[1].strip()
                for line in response.text.splitlines()
                if line.lower().startswith("disallow:")
            ]
            if disallow_paths:
                findings.append(
                    {
                        "id": "F-ROBOTS-HINTS",
                        "target": base + "/robots.txt",
                        "severity": "Info",
                        "title": "robots.txt enthält Disallow-Pfade (Recon-Hilfe für Angreifer)",
                        "evidence": str(disallow_paths[:10]),
                        "description": "Disallow-Pfade sind kein Security-Mechanismus und können eher als Roadmap dienen.",
                    }
                )
                discovered.extend(disallow_paths)
    except Exception:
        pass

    try:
        response = requests.get(base + "/sitemap.xml", timeout=10)
        if response.status_code == 200 and "xml" in response.headers.get("Content-Type", ""):
            try:
                root = ET.fromstring(response.content)
                urls = [element.text for element in root.iter() if element.tag.endswith("}loc") and element.text]
                if len(urls) > 100:
                    findings.append(
                        {
                            "id": "F-SITEMAP-LARGE",
                            "target": base + "/sitemap.xml",
                            "severity": "Info",
                            "title": f"Sitemap listet {len(urls)} URLs",
                            "evidence": f"{len(urls)} URLs",
                        }
                    )
                discovered.extend(urls)
            except Exception:
                pass
    except Exception:
        pass

    write_text_artifact("discovered_urls.txt", "\n".join(discovered))
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    out = {
        "script": "07_robots_sitemap.py",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "findings": audit(target),
    }
    filename = write_script_output("07_robots", out)
    print(f"[+] {len(out['findings'])} findings -> {filename}")
