"""Tech-Fingerprinting: Server, Framework, CMS."""
import json
import pathlib
import re
import sys
import time
from datetime import datetime, timezone

import requests
from auditlib import default_target, write_script_output


def audit(url):
    findings = []
    try:
        response = requests.get(url, timeout=10)
    except Exception as exc:
        return [{"id": "F-FP-ERR", "severity": "Info", "title": str(exc), "target": url}]

    headers = response.headers
    body = response.text[:50000]
    fingerprint = {
        "server": headers.get("Server", ""),
        "x_powered_by": headers.get("X-Powered-By", ""),
        "set_cookie_names": [cookie.split("=")[0] for cookie in headers.get("Set-Cookie", "").split(",") if cookie],
        "via": headers.get("Via", ""),
        "framework_hints": [],
    }

    hints = [
        (r"wp-content|wp-includes", "WordPress"),
        (r"drupal-settings-json|sites/default/files", "Drupal"),
        (r"/_next/|__next_f", "Next.js"),
        (r"nuxt|__nuxt__", "Nuxt.js"),
        (r"react|__reactcontainer", "React"),
        (r"angular|ng-version", "Angular"),
        (r"vue|__vue__", "Vue"),
        (r"x-caddy|caddy", "Caddy"),
        (r"laravel_session|XSRF-TOKEN", "Laravel"),
        (r"django|csrftoken", "Django"),
        (r"rails|_session", "Rails"),
        (r"fastapi|swagger", "FastAPI"),
    ]
    full = body + " " + " ".join(headers.values())
    for pattern, name in hints:
        if re.search(pattern, full, re.IGNORECASE):
            fingerprint["framework_hints"].append(name)

    findings.append(
        {
            "id": "F-FP-INFO",
            "target": url,
            "severity": "Info",
            "title": f"Tech-Stack: {', '.join(fingerprint['framework_hints']) or 'unbekannt'}",
            "evidence": json.dumps(fingerprint, ensure_ascii=False),
        }
    )
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    out = {
        "script": "14_tech_fingerprint.py",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "findings": audit(target),
    }
    filename = write_script_output("14_tech", out)
    print(f"[+] {len(out['findings'])} findings -> {filename}")
