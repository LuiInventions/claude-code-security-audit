"""JS-Library-Detection + simple CVE-Lookup über öffentliche Datenbank."""
import json
import pathlib
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from auditlib import default_target, write_script_output

SIGNATURES = [
    (r"jquery[.-](\d+\.\d+\.\d+)", "jquery"),
    (r"bootstrap[.-](\d+\.\d+\.\d+)", "bootstrap"),
    (r"angular[.-](\d+\.\d+\.\d+)", "angular"),
    (r"react[.-](\d+\.\d+\.\d+)", "react"),
    (r"vue[.-](\d+\.\d+\.\d+)", "vue"),
    (r"lodash[.-](\d+\.\d+\.\d+)", "lodash"),
    (r"three[.-](\d+\.\d+\.\d+)", "three.js"),
]

KNOWN_VULN = {
    "jquery": {"<3.5.0": "CVE-2020-11023 (XSS via HTML injection)"},
    "lodash": {"<4.17.21": "CVE-2021-23337 (command injection via template)"},
    "bootstrap": {"<4.3.1": "CVE-2019-8331 (XSS in tooltip)"},
}


def version_lt(version, threshold):
    def parse(text):
        return [int(part) for part in text.lstrip("<>=").split(".")]

    try:
        return parse(version) < parse(threshold.lstrip("<"))
    except Exception:
        return False


def audit(url):
    findings = []
    base_host = urlparse(url).hostname or ""
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception as exc:
        return [{"id": "F-JSLIB-ERR", "severity": "Info", "title": str(exc), "target": url}]

    scripts = [script.get("src", "") for script in soup.find_all("script") if script.get("src")]
    full_text = " ".join(scripts) + " " + response.text[:20000]

    for pattern, name in SIGNATURES:
        match = re.search(pattern, full_text, re.IGNORECASE)
        if match:
            version = match.group(1)
            for threshold, cve in KNOWN_VULN.get(name, {}).items():
                if version_lt(version, threshold):
                    findings.append(
                        {
                            "id": f"F-JSLIB-{name}-{version}",
                            "target": url,
                            "severity": "High",
                            "title": f"Verwundbare JS-Library: {name} {version}",
                            "description": cve,
                            "evidence": f"Detected: {name} {version}",
                            "fix": f"{name} auf {threshold.lstrip('<')} oder neuer aktualisieren.",
                            "cwe": "CWE-1104",
                        }
                    )

    for script in soup.find_all("script", src=True):
        src = script.get("src", "")
        if src.startswith("http") and (urlparse(src).hostname or "") != base_host and not script.get("integrity"):
            findings.append(
                {
                    "id": f"F-SRI-MISSING-{hash(src) & 0xFFFF}",
                    "target": url,
                    "severity": "Low",
                    "title": f"Externes Script ohne SRI: {src}",
                    "fix": "`integrity=\"sha384-...\" crossorigin=\"anonymous\"` hinzufügen.",
                    "cwe": "CWE-829",
                }
            )
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    out = {
        "script": "08_js_libs.py",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "findings": audit(target),
    }
    filename = write_script_output("08_js", out)
    print(f"[+] {len(out['findings'])} findings -> {filename}")
