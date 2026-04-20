"""Cookie-Audit: Secure, HttpOnly, SameSite, Prefix."""
import json
import pathlib
import sys
import time
from datetime import datetime, timezone

import requests
from auditlib import default_target, write_script_output


def audit(url):
    findings = []
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
    except Exception as exc:
        return [{"id": "F-COOKIE-ERR", "severity": "Info", "title": str(exc), "target": url}]

    cookies = response.cookies
    is_https = url.startswith("https://")
    for cookie in cookies:
        problems = []
        if is_https and not cookie.secure:
            problems.append("Secure fehlt")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            problems.append("HttpOnly fehlt")
        same_site = cookie._rest.get("SameSite", "") if hasattr(cookie, "_rest") else ""
        if not same_site:
            problems.append("SameSite fehlt")
        if cookie.name.startswith("__Host-") and (not cookie.secure or cookie.path != "/"):
            problems.append("__Host- Prefix-Kontrakt verletzt")

        if problems:
            findings.append(
                {
                    "id": f"F-COOKIE-{cookie.name}",
                    "target": url,
                    "severity": "Medium",
                    "title": f"Cookie `{cookie.name}` unsicher: {', '.join(problems)}",
                    "fix": "Cookie mit `Secure; HttpOnly; SameSite=Lax` oder `Strict` setzen.",
                    "cwe": "CWE-1004",
                }
            )
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    out = {
        "script": "06_cookie_audit.py",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "findings": audit(target),
    }
    filename = write_script_output("06_cookies", out)
    print(f"[+] {len(out['findings'])} findings -> {filename}")
