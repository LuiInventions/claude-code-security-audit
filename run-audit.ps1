param([string]$target = "")
Set-Location $PSScriptRoot
if (-not (Test-Path "config.json") -and (Test-Path "config.example.json")) {
    Copy-Item "config.example.json" "config.json"
}
if (-not $target) {
    $config = Get-Content config.json | ConvertFrom-Json
    $target = $config.allowed_targets[0]
}

$python = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }
$runMeta = & $python "scripts/20_run_context.py" start $target | ConvertFrom-Json

Write-Host "=== Audit: $target ===" -ForegroundColor Cyan
$scripts = @(
    "11_crawler", "07_robots_sitemap", "13_dns_recon", "14_tech_fingerprint",
    "17_inventory", "18_dispatcher",
    "01_headers", "02_exposed_files", "03_tls_check", "04_csp_analyzer",
    "05_cors_check", "06_cookie_audit", "08_js_libs", "09_form_probe",
    "10_http_methods", "12_open_redirect",
    "21_api_discovery", "22_auth_surface", "23_authz_idor", "24_csrf_workflows",
    "25_upload_download", "26_reflection_probe", "27_injection_signals",
    "28_bundle_secrets", "29_client_routes", "30_subdomain_hosts",
    "31_rate_limit_abuse", "16_exploitability", "32_report_correlator"
)

foreach ($s in $scripts) {
    Write-Host "[*] $s..." -ForegroundColor Yellow
    & $python "scripts/$s.py" $target
    if ($LASTEXITCODE -ne 0) {
        throw "Script $s ist mit Exit-Code $LASTEXITCODE fehlgeschlagen."
    }
}

Write-Host "[*] Report generieren..." -ForegroundColor Green
& $python "scripts/15_report_generator.py"
if ($LASTEXITCODE -ne 0) {
    throw "Report-Generierung fehlgeschlagen."
}
Write-Host "[*] CI-Gate (Critical)..." -ForegroundColor DarkCyan
& $python "scripts/33_ci_gate.py" "Critical"
Write-Host "Run-ID: $($runMeta.run_id)" -ForegroundColor DarkGray
Write-Host "=== Fertig - siehe reports/ ===" -ForegroundColor Cyan
