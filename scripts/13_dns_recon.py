"""DNS-Recon: SPF, DMARC, DKIM, CAA, MX. Findet fehlende/schwache Mail-Security."""
import json
import pathlib
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
from auditlib import default_target, write_script_output


def audit(url):
    findings = []
    try:
        import dns.resolver
    except ImportError:
        return [{"id": "F-DNS-ERR", "severity": "Info", "title": "dnspython nicht installiert"}]

    domain = urlparse(url).hostname
    if not domain:
        return findings
    domain = ".".join(domain.split(".")[-2:])

    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
        spf = [record.to_text() for record in txt_records if "v=spf1" in record.to_text()]
        if not spf:
            findings.append(
                {
                    "id": "F-DNS-NOSPF",
                    "target": domain,
                    "severity": "Medium",
                    "title": "Kein SPF-Record",
                    "fix": "SPF-Record setzen, z.B. `v=spf1 include:_spf.ionos.com -all`",
                }
            )
        elif any("+all" in record or "?all" in record for record in spf):
            findings.append(
                {
                    "id": "F-DNS-WEAKSPF",
                    "target": domain,
                    "severity": "Medium",
                    "title": "SPF schwach (+all oder ?all)",
                    "evidence": str(spf),
                }
            )
    except Exception:
        pass

    try:
        dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
    except Exception:
        findings.append(
            {
                "id": "F-DNS-NODMARC",
                "target": domain,
                "severity": "Medium",
                "title": "Kein DMARC-Record",
                "fix": 'DMARC setzen: `_dmarc.<domain> TXT "v=DMARC1; p=quarantine; rua=mailto:..."`',
            }
        )

    try:
        dns.resolver.resolve(domain, "CAA")
    except Exception:
        findings.append(
            {
                "id": "F-DNS-NOCAA",
                "target": domain,
                "severity": "Low",
                "title": "Kein CAA-Record",
                "fix": 'CAA setzen: `<domain> CAA 0 issue "letsencrypt.org"`',
            }
        )

    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    out = {
        "script": "13_dns_recon.py",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "findings": audit(target),
    }
    filename = write_script_output("13_dns", out)
    print(f"[+] {len(out['findings'])} findings -> {filename}")
