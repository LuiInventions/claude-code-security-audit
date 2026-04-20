#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# 1. Ensure config.json exists
if [ ! -f config.json ] && [ -f config.example.json ]; then
    cp config.example.json config.json
fi

# 2. Find Python
python_bin="python3"
if [ -x ".venv/bin/python3" ]; then
    python_bin=".venv/bin/python3"
elif [ -x ".venv/bin/python" ]; then
    python_bin=".venv/bin/python"
fi

# 3. Check for Claude Code
if ! command -v claude >/dev/null 2>&1; then
    echo "Error: 'claude' command not found. Please install Claude Code: npm install -g @anthropic-ai/claude-code"
    exit 1
fi

# 4. Get Target URL
target_url=""
if [ $# -ge 1 ]; then
    target_url="$1"
else
    read -p "Welche URL soll getestet werden: " target_url
fi

if [ -z "$target_url" ]; then
    echo "Error: Keine URL angegeben."
    exit 1
fi

# 5. Prepare target
echo "[*] Bereite Ziel vor: $target_url"
normalized_target=$("$python_bin" "scripts/00_prepare_target.py" "$target_url")

# 6. Launch Claude Code
prompt="Führe den kompletten Audit-Workflow gemäß CLAUDE.md für \`config.json.allowed_targets[0]\` aus.

Pflicht:
- Arbeite ausschließlich gegen \`config.json.allowed_targets[0]\`.
- Nutze den Projekt-Workflow und generiere am Ende den HTML-Report.
- Erzeuge zusammen mit dem Report immer auch den Coding-Agent-Remediation-Prompt.
- Ergänze standardmäßig die sichere Exploitability-Bewertung: bestätigte Ausnutzbarkeit, bekannte öffentliche CVEs/Advisories, realistischer Impact, Angreifervoraussetzungen und High-Level-Angriffsablauf.
- Keine operativen Exploit-Schritte, keine Payloads, keine Weaponization.
- Wenn Skripte fehlen oder verbessert werden müssen, passe das Projekt im Workspace an und führe dann den Audit sauber zu Ende.
- Antworte zum Schluss kurz auf Deutsch mit Severity-Zusammenfassung, Reportpfad und Promptpfad.

Ziel: $normalized_target"

echo "=== Claude Code Audit startet für $normalized_target ==="
claude --dangerously-skip-permissions -p "$prompt"

# 7. Check for result
# (Report opening in Linux is variable, but we'll try xdg-open)
latest_report=$(ls -t reports/*.html 2>/dev/null | head -n 1) || true
if [ -n "$latest_report" ]; then
    echo "=== Audit abgeschlossen. Report: $latest_report ==="
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$latest_report"
    fi
fi
