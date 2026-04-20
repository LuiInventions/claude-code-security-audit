param(
    [switch]$InstallKatana
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path "config.json")) {
    Copy-Item "config.example.json" "config.json"
    Write-Host "config.json wurde aus config.example.json erstellt." -ForegroundColor Green
}

$python = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } elseif (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { $null }
if (-not $python) {
    throw "Python wurde nicht gefunden. Bitte Python 3.11+ installieren."
}

if (-not (Test-Path ".venv\\Scripts\\python.exe")) {
    & $python -m venv .venv
}

$venvPython = ".venv\\Scripts\\python.exe"
& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install -r requirements.txt

if (-not (Test-Path "tools")) {
    New-Item -ItemType Directory -Path "tools" | Out-Null
}

if ($InstallKatana -and -not (Test-Path "tools\\katana.exe")) {
    Write-Warning "Katana muss manuell nach tools\\katana.exe abgelegt oder global installiert werden."
}

Write-Host "Setup abgeschlossen. Bitte config.json mit deinen freigegebenen Domains befuellen." -ForegroundColor Cyan
