param(
    [string]$TargetUrl = ""
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path "config.json") -and (Test-Path "config.example.json")) {
    Copy-Item "config.example.json" "config.json"
}

$python = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }
$claude = (Get-Command claude -ErrorAction Stop).Source

if (-not $TargetUrl) {
    $TargetUrl = Read-Host "Welche URL soll getestet werden"
}

$beforeReports = @()
if (Test-Path "reports") {
    $beforeReports = Get-ChildItem "reports" -Filter *.html -File | Select-Object -ExpandProperty FullName
}

$normalizedTarget = & $python "scripts/00_prepare_target.py" $TargetUrl
if ($LASTEXITCODE -ne 0) {
    throw "Ziel konnte nicht vorbereitet werden."
}

$prompt = @"
Führe den kompletten Audit-Workflow gemäß CLAUDE.md für `config.json.allowed_targets[0]` aus.

Pflicht:
- Arbeite ausschließlich gegen `config.json.allowed_targets[0]`.
- Nutze den Projekt-Workflow und generiere am Ende den HTML-Report.
- Erzeuge zusammen mit dem Report immer auch den Coding-Agent-Remediation-Prompt.
- Ergänze standardmäßig die sichere Exploitability-Bewertung: bestätigte Ausnutzbarkeit, bekannte öffentliche CVEs/Advisories, realistischer Impact, Angreifervoraussetzungen und High-Level-Angriffsablauf.
- Keine operativen Exploit-Schritte, keine Payloads, keine Weaponization.
- Wenn Skripte fehlen oder verbessert werden müssen, passe das Projekt im Workspace an und führe dann den Audit sauber zu Ende.
- Antworte zum Schluss kurz auf Deutsch mit Severity-Zusammenfassung, Reportpfad und Promptpfad.

Ziel: $normalizedTarget
"@

Write-Host ""
Write-Host "=== Claude Code Audit startet für $normalizedTarget ===" -ForegroundColor Cyan
& $claude --dangerously-skip-permissions -p $prompt
$exitCode = $LASTEXITCODE

if ($exitCode -ne 0) {
    throw "Claude Code wurde mit Exit-Code $exitCode beendet."
}

$afterReports = Get-ChildItem "reports" -Filter *.html -File | Sort-Object LastWriteTimeUtc -Descending
$newestReport = $afterReports | Where-Object { $beforeReports -notcontains $_.FullName } | Select-Object -First 1
if (-not $newestReport) {
    $newestReport = $afterReports | Select-Object -First 1
}

if ($newestReport) {
    Write-Host "=== Öffne Report: $($newestReport.FullName) ===" -ForegroundColor Green
    Invoke-Item $newestReport.FullName
} else {
    Write-Warning "Kein HTML-Report unter reports/ gefunden."
}
