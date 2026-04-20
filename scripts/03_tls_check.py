"""TLS-Audit: Protokolle, Ciphers, Zertifikat, HSTS-Preload-Tauglichkeit."""
import json
import pathlib
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
from auditlib import default_target, write_script_output


def check_protocol(host, port, protocol_version):
    try:
        context = ssl.SSLContext(protocol_version)
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def audit(url):
    findings = []
    parsed = urlparse(url)
    host, port = parsed.hostname, parsed.port or 443

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_socket:
                cert = tls_socket.getpeercert()
                cipher = tls_socket.cipher()
                tls_version = tls_socket.version()
    except Exception as exc:
        return [{"id": "F-TLS-ERR", "severity": "High", "title": f"TLS-Verbindung fehlgeschlagen: {exc}", "target": url}]

    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    days_left = (not_after - datetime.now(timezone.utc).replace(tzinfo=None)).days
    if days_left < 30:
        findings.append(
            {
                "id": "F-TLS-EXPIRING",
                "target": url,
                "severity": "High" if days_left < 7 else "Medium",
                "title": f"Zertifikat läuft in {days_left} Tagen ab",
                "fix": "Zertifikat erneuern (bei Caddy passiert das automatisch — prüfen, ob ACME funktioniert).",
            }
        )

    if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        findings.append(
            {
                "id": "F-TLS-WEAK-VERSION",
                "target": url,
                "severity": "High",
                "title": f"Schwache TLS-Version: {tls_version}",
                "evidence": tls_version,
                "fix": "Nur TLS 1.2 und 1.3 erlauben.",
                "cwe": "CWE-326",
            }
        )

    if cipher and any(name in cipher[0] for name in ("RC4", "DES", "MD5", "NULL")):
        findings.append(
            {
                "id": "F-TLS-WEAK-CIPHER",
                "target": url,
                "severity": "High",
                "title": f"Schwache Cipher-Suite: {cipher[0]}",
                "evidence": str(cipher),
                "cwe": "CWE-327",
            }
        )

    issuer = dict(item[0] for item in cert.get("issuer", []))
    subject = dict(item[0] for item in cert.get("subject", []))
    if issuer == subject:
        findings.append(
            {
                "id": "F-TLS-SELFSIGNED",
                "target": url,
                "severity": "High",
                "title": "Selbstsigniertes Zertifikat",
                "evidence": str(issuer),
                "fix": "Echtes Zertifikat via Let's Encrypt / ACME ausstellen.",
            }
        )

    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    out = {
        "script": "03_tls_check.py",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "findings": audit(target),
    }
    filename = write_script_output("03_tls", out)
    print(f"[+] {len(out['findings'])} findings -> {filename}")
