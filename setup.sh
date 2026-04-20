#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f config.json ]; then
  cp config.example.json config.json
  echo "config.json wurde aus config.example.json erstellt."
fi

python_bin="${PYTHON_BIN:-python3}"
if ! command -v "$python_bin" >/dev/null 2>&1; then
  echo "Python 3.11+ wurde nicht gefunden." >&2
  exit 1
fi

if [ ! -x ".venv/bin/python3" ] && [ ! -x ".venv/bin/python" ]; then
  "$python_bin" -m venv .venv
fi

if [ -x ".venv/bin/python3" ]; then
  venv_python=".venv/bin/python3"
else
  venv_python=".venv/bin/python"
fi

"$venv_python" -m pip install --upgrade pip
"$venv_python" -m pip install -r requirements.txt

mkdir -p tools findings reports
echo "Setup abgeschlossen. Bitte config.json mit deinen freigegebenen Domains befuellen."
