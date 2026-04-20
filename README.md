# 🔐 sec-audit

Portable, defensive security audit toolkit for websites and web APIs on **authorized targets only**.

`sec-audit` is built for practical repo use:
- ✅ GitHub-ready structure
- ✅ Windows and Linux/macOS setup scripts
- ✅ isolated run artifacts
- ✅ HTML report output
- ✅ separate remediation prompt for a coding agent
- ✅ no hardcoded local user paths in the project code

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

## 🧭 High-Level Workflow

The default audit pipeline is:

1. **Recon**
   Collect URLs, sitemap hints, DNS data, and basic technology fingerprints.
2. **Inventory**
   Build a normalized target inventory of pages, APIs, forms, auth flows, uploads, and hosts.
3. **Baseline Hardening Checks**
   Evaluate headers, TLS, CSP, cookies, exposed files, HTTP methods, JS libraries, and redirects.
4. **Area-Specific Security Checks**
   Analyze API exposure, auth surface, CSRF workflows, authorization hints, upload/download behavior, bundle leaks, client routes, and abuse patterns.
5. **Correlation & Reporting**
   Correlate findings, estimate exploitability, generate an HTML report, and create a remediation prompt for a coding agent.

## 🧰 Feature Overview

### Recon & Discovery

- `scripts/11_crawler.py`
  Crawls the target and stores discovered URLs.
- `scripts/07_robots_sitemap.py`
  Parses `robots.txt` and `sitemap.xml`.
- `scripts/13_dns_recon.py`
  Checks SPF, DMARC, CAA, and related DNS hardening indicators.
- `scripts/14_tech_fingerprint.py`
  Detects high-level server/framework hints.

### Inventory & Dispatch

- `scripts/17_inventory.py`
  Builds a normalized inventory of pages, APIs, forms, auth pages, uploads, downloads, and hosts.
- `scripts/18_dispatcher.py`
  Maps the inventory into test scopes for downstream scripts.
- `scripts/20_run_context.py`
  Creates isolated run directories and metadata.
- `scripts/auditlib.py`
  Shared helper layer for config loading, run paths, rate-limited HTTP, redaction, and artifact writing.

### Baseline Hardening Checks

- `scripts/01_headers.py`
  Security header presence and weakness checks.
- `scripts/02_exposed_files.py`
  Probes common public files and exposed paths.
- `scripts/03_tls_check.py`
  Checks certificate expiry, weak TLS versions, weak ciphers, and self-signed certs.
- `scripts/04_csp_analyzer.py`
  Parses CSP and highlights risky directives like `unsafe-inline`.
- `scripts/05_cors_check.py`
  Tests permissive or reflected CORS behavior.
- `scripts/06_cookie_audit.py`
  Reviews cookie flags such as `Secure`, `HttpOnly`, and `SameSite`.
- `scripts/08_js_libs.py`
  Detects common JS libraries and known vulnerable versions.
- `scripts/09_form_probe.py`
  Safely checks form/API endpoints for origin handling and simple rate-limit behavior.
- `scripts/10_http_methods.py`
  Enumerates risky HTTP methods.
- `scripts/12_open_redirect.py`
  Checks common redirect parameters for open redirect behavior.

### Area-Specific Security Checks

- `scripts/21_api_discovery.py`
  Looks for exposed API docs, JSON surfaces, and GraphQL behavior.
- `scripts/22_auth_surface.py`
  Reviews login/reset/logout flows for weak patterns like bad caching or missing CSRF hints.
- `scripts/23_authz_idor.py`
  Performs safe heuristics for object-level authorization gaps.
- `scripts/24_csrf_workflows.py`
  Inspects state-changing forms for missing CSRF signals.
- `scripts/25_upload_download.py`
  Checks upload/download workflows for public exposure and weak protection signals.
- `scripts/26_reflection_probe.py`
  Uses a harmless canary to detect unsafe reflection contexts.
- `scripts/27_injection_signals.py`
  Searches for stack traces and error disclosures that often support injection findings.
- `scripts/28_bundle_secrets.py`
  Scans bundles and source maps for secret or infrastructure leak patterns.
- `scripts/29_client_routes.py`
  Reviews client routes, special frontend resources, and route-level header drift.
- `scripts/30_subdomain_hosts.py`
  Extends coverage to reachable host variants and subdomains.
- `scripts/31_rate_limit_abuse.py`
  Checks whether sensitive technical endpoints appear to lack meaningful throttling.

### Correlation, Reporting & Gating

- `scripts/16_exploitability.py`
  Adds defensive, high-level exploitability context to relevant findings.
- `scripts/32_report_correlator.py`
  Correlates findings into combined risk chains.
- `scripts/15_report_generator.py`
  Generates the HTML report and the remediation prompt for a coding agent.
- `scripts/33_ci_gate.py`
  Allows simple severity gating for CI-style workflows.

## 🚀 Quick Start

### Windows

```powershell
./setup.ps1
notepad config.json
./run-audit.ps1
```

### Linux / macOS

```bash
chmod +x setup.sh run-audit.sh
./setup.sh
$EDITOR config.json
./run-audit.sh
```

If `config.json` does not exist, it is created automatically from `config.example.json`.

## ⚙️ Configuration

Main settings live in `config.json`.

Important fields:
- `allowed_targets`
  Only domains explicitly authorized for testing.
- `crawl.max_depth`
  Maximum crawl depth.
- `crawl.max_urls`
  URL budget for discovery.
- `crawl.timeout_seconds`
  Per-request timeout.
- `crawl.user_agent`
  Audit user agent string. You should personalize this.
- `rate_limit.requests_per_second`
  Max request rate used by the shared HTTP client.
- `rate_limit.pause_on_429_seconds`
  Backoff when the target returns `429`.
- `excluded_paths`
  Paths that should never be actively tested.

## 📦 Setup Scripts

- `setup.ps1`
  Creates `.venv`, installs Python dependencies, and seeds `config.json`.
- `setup.sh`
  Unix equivalent of the same bootstrap flow.
- `launch-website-audit.ps1`
  Starts a Claude-driven audit flow on Windows.
- `launch-website-audit.bat`
  Convenience wrapper for the PowerShell launcher.

## 🧰 GitHub Readiness

This repository is prepared for clean public or team-internal GitHub use:

- `config.json` is ignored so local target scopes and personal audit settings stay private.
- generated findings, reports, prompts, logs, caches, and virtual environments are ignored.
- `.gitattributes` normalizes text and script line endings across Windows and Unix environments.
- `.github/workflows/ci.yml` runs a lightweight CI check for dependency install, Python compilation, and run-context smoke validation.
- `LICENSE` and `CONTRIBUTING.md` are included for repo hygiene and collaboration.

## 🗂️ Output Structure

Each audit run gets its own run ID.

Run-local artifacts:
- `findings/runs/<run_id>/...`
- `reports/runs/<run_id>/report.html`
- `reports/runs/<run_id>/coding_agent_prompt.txt`

Top-level convenience artifacts:
- `reports/<run_id>_<timestamp>.html`
- `reports/<run_id>_<timestamp>_coding_agent_prompt.txt`

## 🤖 Coding-Agent Prompt

Every generated report is paired with a **dedicated remediation prompt** for a coding agent.

That prompt explains:
- which findings were identified
- which issues should be fixed first
- the technical remediation direction
- that tests must be added or updated
- which remaining risks should be manually retested

## 🛡️ Safety Model

This toolkit is intentionally defensive:
- no brute-force attacks
- no destructive exploit payloads
- no weaponization guidance
- no active exploit instructions in the report
- secrets are redacted where possible

## 🕷️ Optional: Katana

For better crawling coverage, install `katana`.

### Windows

Place:
- `katana.exe` at `tools/katana.exe`

### Linux / macOS

```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

If `katana` is missing, the toolkit still works with reduced discovery coverage.

## 📘 Repo Notes

- `.venv` is ignored and should not be committed.
- `config.json` is local-only and should not be committed.
- run artifacts under `findings/runs/` and `reports/runs/` are ignored.
- top-level generated HTML reports and coding-agent prompts are ignored.
- local downloaded binaries such as `tools/katana.exe` are ignored.
- the repo includes `.gitkeep` files so the output directories exist cleanly on GitHub.

## ✅ Current Status

The project now includes:
- a multi-phase audit architecture
- run isolation
- report generation
- coding-agent remediation prompt generation
- setup scripts
- portable repo structure

It is a strong base for production-oriented web security reviews, while still relying on **safe heuristics** in several advanced checks.
