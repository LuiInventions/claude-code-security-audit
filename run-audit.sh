#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

python_bin="${PYTHON_BIN:-python3}"
if [ -x ".venv/bin/python3" ]; then
  python_bin=".venv/bin/python3"
elif [ -x ".venv/bin/python" ]; then
  python_bin=".venv/bin/python"
fi

target="${1:-$("$python_bin" - <<'PY'
import json, pathlib
config = json.loads(pathlib.Path("config.json").read_text(encoding="utf-8"))
print(config["allowed_targets"][0])
PY
)}"

run_meta="$("$python_bin" scripts/20_run_context.py start "$target")"
echo "=== Audit: $target ==="
for s in 11_crawler 07_robots_sitemap 13_dns_recon 14_tech_fingerprint \
         17_inventory 18_dispatcher \
         01_headers 02_exposed_files 03_tls_check 04_csp_analyzer \
         05_cors_check 06_cookie_audit 08_js_libs 09_form_probe \
         10_http_methods 12_open_redirect \
         21_api_discovery 22_auth_surface 23_authz_idor 24_csrf_workflows \
         25_upload_download 26_reflection_probe 27_injection_signals \
         28_bundle_secrets 29_client_routes 30_subdomain_hosts \
         31_rate_limit_abuse 16_exploitability 32_report_correlator; do
  echo "[*] $s..."
  "$python_bin" "scripts/$s.py" "$target"
done

"$python_bin" scripts/15_report_generator.py
"$python_bin" scripts/33_ci_gate.py Critical || true
echo "Run-Metadaten: $run_meta"
echo "=== Fertig - siehe reports/ ==="
