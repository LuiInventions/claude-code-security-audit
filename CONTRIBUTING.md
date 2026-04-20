# Contributing

Thanks for contributing to `sec-audit`.

## Ground Rules

- Only add defensive, non-destructive checks.
- Never add exploit payloads, weaponization steps, brute-force logic, or destructive actions.
- Keep all active requests inside `config.json.allowed_targets`.
- Preserve rate limiting and redaction behavior.

## Local Setup

### Windows

```powershell
./setup.ps1
./run-audit.ps1
```

### Linux / macOS

```bash
chmod +x setup.sh run-audit.sh
./setup.sh
./run-audit.sh
```

## Pull Request Checklist

- Add or update tests or verification steps when behavior changes.
- Keep the repo free of local artifacts, reports, findings, secrets, and personal config.
- Update `README.md` and `CLAUDE.md` when scripts or workflow phases change.
- Make sure new scripts write run-isolated artifacts through `scripts/auditlib.py`.
- Keep language defensive and remediation-focused.
