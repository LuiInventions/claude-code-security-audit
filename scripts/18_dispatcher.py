"""Leitet das Inventory in ausfuehrbare Testbereiche pro Script ueber."""
from __future__ import annotations

import json
import sys

from auditlib import build_finding, default_target, load_inventory, now_iso, write_script_output, write_text_artifact


def build_dispatch_plan(target: str) -> tuple[dict, list[dict]]:
    inventory = load_inventory()
    dispatch_plan = {
        "target": target,
        "generated_at": now_iso(),
        "root_checks": ["01_headers", "02_exposed_files", "03_tls_check", "04_csp_analyzer", "06_cookie_audit"],
        "inventory_checks": {
            "21_api_discovery": inventory.get("api_urls", []),
            "22_auth_surface": inventory.get("auth_urls", []),
            "23_authz_idor": inventory.get("api_urls", []) + inventory.get("download_urls", []),
            "24_csrf_workflows": [form.get("action") for form in inventory.get("forms", [])],
            "25_upload_download": inventory.get("upload_urls", []) + inventory.get("download_urls", []),
            "26_reflection_probe": inventory.get("page_urls", []),
            "27_injection_signals": inventory.get("page_urls", []) + inventory.get("api_urls", []),
            "28_bundle_secrets": inventory.get("asset_urls", []),
            "29_client_routes": inventory.get("page_urls", []),
            "30_subdomain_hosts": inventory.get("hosts", []),
            "31_rate_limit_abuse": inventory.get("api_urls", []) + inventory.get("auth_urls", []),
        },
    }
    findings = [
        build_finding(
            "F-DISPATCH-PLAN",
            target,
            "Dispatch-Plan fuer Bereichs-Skripte erzeugt",
            "Info",
            description="Jeder Security-Bereich bekommt jetzt eine eigene automatische Zielmenge aus dem Inventory.",
            evidence=json.dumps(
                {key: len(value) for key, value in dispatch_plan["inventory_checks"].items()},
                ensure_ascii=False,
            ),
        )
    ]
    return dispatch_plan, findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    plan, findings = build_dispatch_plan(target)
    write_text_artifact("dispatch_plan.json", json.dumps(plan, indent=2, ensure_ascii=False) + "\n")
    payload = {
        "script": "18_dispatcher.py",
        "timestamp": now_iso(),
        "target": target,
        "findings": findings,
    }
    filename = write_script_output("18_dispatcher", payload)
    print(f"[+] Dispatch-Plan gespeichert -> {filename}")
