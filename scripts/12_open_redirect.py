"""Open-Redirect-Tests. Probiert typische Redirect-Parameter."""
import json
import pathlib
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from auditlib import default_target, write_script_output

PARAMS = ["url", "redirect", "redirect_uri", "next", "return", "returnUrl", "continue", "dest", "target"]
PAYLOAD = "https://evil-redirect-test.example.com/"


def audit(url):
    findings = []
    for param in PARAMS:
        test_url = f"{url.rstrip('/')}/?{param}={PAYLOAD}"
        try:
            response = requests.get(test_url, timeout=10, allow_redirects=False)
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location", "")
                parsed = urlparse(location)
                if "evil-redirect-test" in location and parsed.scheme.startswith("http"):
                    findings.append(
                        {
                            "id": f"F-OPENREDIR-{param}",
                            "target": test_url,
                            "severity": "Medium",
                            "title": f"Open Redirect via Parameter `{param}`",
                            "evidence": f"Location: {location}",
                            "fix": "Redirect-Targets gegen Whitelist prüfen oder relative Pfade erzwingen.",
                            "cwe": "CWE-601",
                        }
                    )
        except Exception:
            continue
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    out = {
        "script": "12_open_redirect.py",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "findings": audit(target),
    }
    filename = write_script_output("12_redir", out)
    print(f"[+] {len(out['findings'])} findings -> {filename}")
