"""Gemeinsame Hilfsfunktionen fuer den Website-Security-Audit."""
from __future__ import annotations

import json
import os
import pathlib
import re
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

ROOT = pathlib.Path(__file__).resolve().parent.parent
FINDINGS_ROOT = ROOT / "findings"
REPORTS_ROOT = ROOT / "reports"
CURRENT_RUN_FILE = FINDINGS_ROOT / "current_run.json"
AUXILIARY_FILES = {"inventory.json", "dispatch_plan.json", "metadata.json", "summary.json"}


def repo_root() -> pathlib.Path:
    return ROOT


def load_config() -> dict[str, Any]:
    config_path = ROOT / "config.json"
    if not config_path.exists():
        example_path = ROOT / "config.example.json"
        if not example_path.exists():
            raise FileNotFoundError("config.json und config.example.json fehlen.")
        config_path.write_text(example_path.read_text(encoding="utf-8"), encoding="utf-8")
    return json.loads(config_path.read_text(encoding="utf-8"))


def default_target() -> str:
    return load_config().get("allowed_targets", [""])[0]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("_") or "artifact"


def normalize_url(raw_url: str, base_url: str | None = None) -> str:
    if not raw_url:
        return ""
    if base_url:
        raw_url = urljoin(base_url, raw_url)
    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ""
    path = parsed.path or "/"
    normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    return normalized.rstrip("/") if path != "/" else normalized


def registrable_domain(hostname: str) -> str:
    parts = (hostname or "").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def allowed_hosts() -> list[str]:
    return [urlparse(url).hostname or "" for url in load_config().get("allowed_targets", [])]


def scope_allows(url: str) -> bool:
    host = urlparse(url).hostname or ""
    for allowed in allowed_hosts():
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def should_exclude_url(url: str) -> bool:
    path = urlparse(url).path or "/"
    for pattern in load_config().get("excluded_paths", []):
        regex = "^" + re.escape(pattern).replace("\\*", ".*") + "$"
        if re.match(regex, path):
            return True
    return False


def redact_text(text: str) -> str:
    if not text:
        return text
    patterns = [
        r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[A-Za-z0-9._\-]{8,}['\"]?",
        r"AKIA[0-9A-Z]{16}",
        r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    ]
    redacted = text
    for pattern in patterns:
        redacted = re.sub(pattern, "[REDACTED]", redacted)
    return redacted


def repo_relative_text(value: Any) -> str:
    text = redact_text(str(value))
    root_text = str(ROOT)
    if root_text in text:
        text = text.replace(root_text + os.sep, "")
        text = text.replace(root_text, ".")
    if any(marker in text for marker in ("Ã", "â", "Â")):
        try:
            text = text.encode("latin-1", errors="ignore").decode("utf-8", errors="ignore")
        except Exception:
            pass
    replacements = {
        "Ã¤": "ae",
        "Ã¶": "oe",
        "Ã¼": "ue",
        "Ã„": "Ae",
        "Ã–": "Oe",
        "Ãœ": "Ue",
        "ÃŸ": "ss",
        "Â·": "|",
        "â€”": "-",
        "â€“": "-",
        "â€ž": '"',
        "â€œ": '"',
        "â€™": "'",
        "â€‹": "",
        "ä": "ae",
        "ö": "oe",
        "ü": "ue",
        "Ä": "Ae",
        "Ö": "Oe",
        "Ü": "Ue",
        "ß": "ss",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    return text


def current_run_meta() -> dict[str, Any]:
    if CURRENT_RUN_FILE.exists():
        return json.loads(CURRENT_RUN_FILE.read_text(encoding="utf-8"))
    return {}


def ensure_run_dirs(run_id: str) -> tuple[pathlib.Path, pathlib.Path]:
    findings_dir = FINDINGS_ROOT / "runs" / run_id
    reports_dir = REPORTS_ROOT / "runs" / run_id
    findings_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    return findings_dir, reports_dir


def start_run(target: str) -> dict[str, Any]:
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    findings_dir, reports_dir = ensure_run_dirs(run_id)
    metadata = {
        "run_id": run_id,
        "target": target,
        "created_at": now_iso(),
        "findings_dir": str(findings_dir),
        "reports_dir": str(reports_dir),
    }
    FINDINGS_ROOT.mkdir(exist_ok=True)
    CURRENT_RUN_FILE.write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (findings_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return metadata


def current_run_id(create: bool = False, target: str | None = None) -> str | None:
    env_run_id = os.getenv("SEC_AUDIT_RUN_ID")
    if env_run_id:
        ensure_run_dirs(env_run_id)
        return env_run_id
    meta = current_run_meta()
    if meta.get("run_id"):
        ensure_run_dirs(meta["run_id"])
        return meta["run_id"]
    if create:
        return start_run(target or default_target())["run_id"]
    return None


def run_findings_dir(run_id: str | None = None) -> pathlib.Path:
    active_run = run_id or current_run_id(create=True)
    assert active_run
    return ensure_run_dirs(active_run)[0]


def run_reports_dir(run_id: str | None = None) -> pathlib.Path:
    active_run = run_id or current_run_id(create=True)
    assert active_run
    return ensure_run_dirs(active_run)[1]


def artifact_path(name: str, run_id: str | None = None) -> pathlib.Path:
    path = run_findings_dir(run_id) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def write_script_output(prefix: str, payload: dict[str, Any], run_id: str | None = None) -> pathlib.Path:
    active_run = run_id or current_run_id(create=True, target=payload.get("target"))
    assert active_run
    payload.setdefault("run_id", active_run)
    filename = artifact_path(f"{prefix}_{int(time.time())}.json", active_run)
    filename.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return filename


def write_text_artifact(name: str, content: str, run_id: str | None = None) -> pathlib.Path:
    filename = artifact_path(name, run_id)
    filename.write_text(content, encoding="utf-8")
    return filename


def latest_artifact(pattern: str, run_id: str | None = None) -> pathlib.Path | None:
    files = sorted(run_findings_dir(run_id).glob(pattern), key=lambda item: item.stat().st_mtime, reverse=True)
    return files[0] if files else None


def result_prefix(file_path: pathlib.Path) -> str:
    match = re.match(r"^(.*)_\d+\.json$", file_path.name)
    return match.group(1) if match else file_path.stem


def iter_run_json(
    run_id: str | None = None,
    include_auxiliary: bool = False,
    latest_only: bool = False,
) -> list[pathlib.Path]:
    files = []
    for file_path in sorted(run_findings_dir(run_id).glob("*.json")):
        if not include_auxiliary and file_path.name in AUXILIARY_FILES:
            continue
        files.append(file_path)
    if not latest_only:
        return files
    selected: dict[str, pathlib.Path] = {}
    for file_path in sorted(files, key=lambda item: item.stat().st_mtime, reverse=True):
        key = result_prefix(file_path)
        if key not in selected:
            selected[key] = file_path
    return sorted(selected.values())


def load_inventory(run_id: str | None = None) -> dict[str, Any]:
    inventory_path = artifact_path("inventory.json", run_id)
    if inventory_path.exists():
        return json.loads(inventory_path.read_text(encoding="utf-8"))
    return {}


def save_inventory(inventory: dict[str, Any], run_id: str | None = None) -> pathlib.Path:
    active_run = run_id or current_run_id(create=True, target=inventory.get("target"))
    assert active_run
    inventory["run_id"] = active_run
    inventory.setdefault("generated_at", now_iso())
    filename = artifact_path("inventory.json", active_run)
    filename.write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return filename


def update_inventory(updates: dict[str, Any], run_id: str | None = None) -> pathlib.Path:
    inventory = load_inventory(run_id)
    inventory.update(updates)
    return save_inventory(inventory, run_id)


def add_inventory_urls(urls: list[str], bucket: str, run_id: str | None = None) -> pathlib.Path:
    inventory = load_inventory(run_id)
    existing = set(inventory.get(bucket, []))
    existing.update(filter(None, urls))
    inventory[bucket] = sorted(existing)
    return save_inventory(inventory, run_id)


def extract_same_scope_urls(urls: list[str], base_url: str) -> list[str]:
    normalized = []
    for item in urls:
        value = normalize_url(item, base_url=base_url)
        if value and scope_allows(value) and not should_exclude_url(value):
            normalized.append(value)
    return sorted(set(normalized))


class RateLimitedHttpClient:
    def __init__(self) -> None:
        config = load_config()
        self.timeout = config.get("crawl", {}).get("timeout_seconds", 10)
        self.rps = max(1, config.get("rate_limit", {}).get("requests_per_second", 5))
        self.pause_on_backoff = config.get("rate_limit", {}).get("pause_on_429_seconds", 30)
        user_agent = config.get("crawl", {}).get("user_agent") or "SecurityAudit/1.0"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self._last_request_at = 0.0

    def _sleep_if_needed(self) -> None:
        min_interval = 1.0 / self.rps
        delta = time.monotonic() - self._last_request_at
        if delta < min_interval:
            time.sleep(min_interval - delta)

    def request(self, method: str, url: str, retry: bool = True, **kwargs: Any) -> requests.Response:
        normalized = normalize_url(url)
        if not normalized or not scope_allows(normalized):
            raise ValueError(f"URL ausserhalb des Scopes: {url}")
        if should_exclude_url(normalized):
            raise ValueError(f"URL ist per excluded_paths ausgeschlossen: {url}")
        self._sleep_if_needed()
        kwargs.setdefault("timeout", self.timeout)
        response = self.session.request(method.upper(), normalized, **kwargs)
        self._last_request_at = time.monotonic()
        if retry and response.status_code in (429, 503):
            time.sleep(self.pause_on_backoff)
            return self.request(method, normalized, retry=False, **kwargs)
        return response

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("POST", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("OPTIONS", url, **kwargs)


def build_finding(
    finding_id: str,
    target: str,
    title: str,
    severity: str = "Info",
    **kwargs: Any,
) -> dict[str, Any]:
    finding = {
        "id": finding_id,
        "target": target,
        "title": title,
        "severity": severity,
    }
    finding.update({key: value for key, value in kwargs.items() if value not in (None, "", [], {})})
    return finding
