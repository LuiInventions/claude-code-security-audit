# 🔐 sec-audit

Portable, defensive security audit toolkit for websites and web APIs on **authorized targets only**.

---

## 🚀 Quick Start

### 1. Clone the Project
```bash
git clone https://github.com/LuiInventions/claude-code-security-audit
```
### 2. Go to Project Folder
```bash
cd claude-code-security-audit
```

### 3. Setup Environment
First, ensure you have **Claude Code** installed (`npm install -g @anthropic-ai/claude-code`) and Python 3.11+.

**Windows:**
```powershell
./setup.ps1
```

**Linux / macOS:**
```bash
chmod +x setup.sh ./setup.sh
```

### 3. Start claude code
Run Claude Code in the project folder

**Windows:**
```
claude
```

## 📋 Prerequisites

To use the automated audit workflow, you need:
- **Claude Code**: The primary AI agent driving the audit. Install via: `npm install -g @anthropic-ai/claude-code`
- **Python 3.11+**: Required for the underlying audit scripts.
- **Git**: For version control and project management.
- **Node.js**: Required for Claude Code.

---

## 🤖 Claude-Integrated Workflow

This project is optimized for use with **Claude Code**. When you run the launch script:
1.  **URL Input**: You enter the target URL (e.g., `https://example.com`).
2.  **Target Preparation**: If the URL is not already in `config.json`, it is added to the `allowed_targets`.
3.  **Claude Launch**: Claude Code starts and reads `CLAUDE.md`, which contains the "laws" and workflow instructions for the audit.
4.  **Autonomous Audit**: Claude executes the Python scripts in sequence, analyzes results, and can even improve scripts or fix issues in real-time.
5.  **Reporting**: Following the audit, Claude generates a JSON finding list, an HTML report, and a specialized remediation prompt for developers.

---

## ✨ What It Does

This toolkit helps you run a **structured, non-destructive web security audit** against domains you are explicitly allowed to test.

It covers:
- 🌐 discovery and crawling
- 🧱 security headers and TLS hardening
- 🍪 cookie and browser policy checks
- 🔄 CORS and redirect behavior
- 🧾 exposed files and misconfigurations
- 🔎 API, auth, CSRF, upload/download surface analysis
- 📦 JavaScript bundle and secret leak checks
- 🛰️ subdomain and host coverage
- 🚦 abuse and rate-limit heuristics
- 🧠 exploitability correlation
- 🛠️ remediation guidance for coding agents

## 🧰 Feature Overview

### Recon & Discovery
- `scripts/11_crawler.py`: Crawls the target and stores discovered URLs.
- `scripts/07_robots_sitemap.py`: Parses `robots.txt` and `sitemap.xml`.
- `scripts/13_dns_recon.py`: Checks SPF, DMARC, CAA, and DNS hardening.
- `scripts/14_tech_fingerprint.py`: Detects server/framework hints.

### Inventory & Dispatch
- `scripts/17_inventory.py`: Builds a normalized inventory of pages, APIs, forms, etc.
- `scripts/18_dispatcher.py`: Maps inventory into test scopes.
- `scripts/20_run_context.py`: Creates isolated run directories.
- `scripts/auditlib.py`: Shared logic for HTTP, rate-limits, and artifact writing.

### Baseline Hardening Checks
- `scripts/01_headers.py`: Security header checks.
- `scripts/02_exposed_files.py`: Probes common public files.
- `scripts/03_tls_check.py`: Certificate and cipher suite audit.
- `scripts/04_csp_analyzer.py`: Highlights risky CSP directives.
- `scripts/05_cors_check.py`: Tests for permissive CORS.
- `scripts/06_cookie_audit.py`: Reviews cookie security flags.
- `scripts/08_js_libs.py`: Detects vulnerable JS libraries.
- `scripts/09_form_probe.py`: Checks origin handling and rate-limits.
- `scripts/10_http_methods.py`: Enumerates risky HTTP methods.
- `scripts/12_open_redirect.py`: Logic-based redirect testing.

### Area-Specific Security Checks
- `scripts/21_api_discovery.py`: JSON/GraphQL/API surface detection.
- `scripts/22_auth_surface.py`: Login/logout flow review.
- `scripts/23_authz_idor.py`: Heuristics for authorization gaps.
- `scripts/24_csrf_workflows.py`: Inspects missing CSRF signals.
- `scripts/25_upload_download.py`: Checks public exposure of file operations.
- `scripts/26_reflection_probe.py`: Harmless canary reflection detection.
- `scripts/27_injection_signals.py`: Identifies disclose-heavy error states.
- `scripts/28_bundle_secrets.py`: Scans for leaked secrets in bundles.
- `scripts/29_client_routes.py`: Frontend route security analysis.
- `scripts/30_subdomain_hosts.py`: Coverage for reachable host variants.
- `scripts/31_rate_limit_abuse.py`: Sensitive endpoint throttling checks.

### Correlation & Reporting
- `scripts/16_exploitability.py`: Adds defensive exploitability context.
- `scripts/32_report_correlator.py`: Correlates findings into risk chains.
- `scripts/15_report_generator.py`: Generates HTML reports and remediation prompts.

## 🛡️ Safety Model

This toolkit is intentionally defensive:
- **No brute-force** attacks.
- **No destructive** exploit payloads.
- **No weaponization** guidance.
- **No active exploit instructions** in reports.
- **Redacted secrets** in artifacts.

## ⚖️ Disclaimer

> [!CAUTION]
> **This software is provided for educational and authorized security auditing purposes only.**
>
> 1.  **Authorization**: You MUST have explicit, written permission from the target's owner before running this toolkit. Unauthorized testing is illegal.
> 2.  **Liability**: The authors and contributors of `sec-audit` assume **no liability** and are **not responsible** for any misuse, damage, data loss, or legal consequences caused by this program.
> 3.  **Safety**: While designed to be non-destructive, any automated tool carries risks. Use at your own risk.
>
> **By using this project, you agree to these terms.**

---

## 🗂️ Output Structure

Each audit run gets a unique Run ID.
- `findings/runs/<run_id>/`: Raw JSON artifacts.
- `reports/runs/<run_id>/report.html`: The main audit result.
- `reports/runs/<run_id>/coding_agent_prompt.txt`: Prompt for code remediation.

## 🕷️ Optional: Katana

For better crawling coverage, install `katana`:
- **Windows**: Place `katana.exe` at `tools/katana.exe`.
- **Linux / macOS**: `go install github.com/projectdiscovery/katana/cmd/katana@latest`

## 📘 Project Hygiene
- `.venv` and `config.json` are ignored (private).
- Generated findings and reports are ignored.
- Use `.gitattributes` to maintain line endings across platforms.
