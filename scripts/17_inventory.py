"""Baut ein zentrales Inventory aller bekannten Seiten, APIs und Workflows."""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup

from auditlib import (
    RateLimitedHttpClient,
    build_finding,
    default_target,
    extract_same_scope_urls,
    latest_artifact,
    load_inventory,
    normalize_url,
    now_iso,
    save_inventory,
    scope_allows,
    should_exclude_url,
    slug,
    write_script_output,
)

COMMON_ENDPOINTS = [
    "/api",
    "/api/contact",
    "/api/v1",
    "/graphql",
    "/openapi.json",
    "/swagger.json",
    "/swagger/index.html",
    "/login",
    "/register",
    "/logout",
    "/forgot-password",
    "/reset-password",
    "/contact",
    "/upload",
    "/download",
]

AUTH_HINTS = ("login", "signin", "signup", "register", "auth", "logout", "password", "reset", "forgot")
API_HINTS = ("/api/", "/graphql", ".json", "/rest/", "/rpc/")
UPLOAD_HINTS = ("upload", "avatar", "attachment", "media")
DOWNLOAD_HINTS = ("download", "export", "invoice", "receipt", "file", "document", "report")
REDIRECT_PARAMS = {"url", "next", "continue", "redirect", "redirect_uri", "return", "dest", "target"}


def extract_form_metadata(html: str, page_url: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = normalize_url(form.get("action") or page_url, base_url=page_url)
        method = (form.get("method") or "GET").upper()
        fields = []
        file_inputs = []
        has_csrf_token = False
        has_password = False
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name") or field.get("id") or field.get("type") or "field"
            fields.append(name)
            if field.get("type") == "file":
                file_inputs.append(name)
            if field.get("type") == "password":
                has_password = True
            if "csrf" in name.lower() or "token" in name.lower():
                has_csrf_token = True
        forms.append(
            {
                "page": page_url,
                "action": action or page_url,
                "method": method,
                "fields": sorted(set(fields)),
                "file_inputs": sorted(set(file_inputs)),
                "has_csrf_token": has_csrf_token,
                "has_password": has_password,
            }
        )
    return forms


def extract_script_urls(html: str, page_url: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    urls = []
    for script in soup.find_all("script", src=True):
        urls.append(script.get("src", ""))
    pattern = re.compile(r"""(?:"|')(\/(?:api|graphql|auth|download|upload)[^"' ]*)(?:"|')""")
    urls.extend(match.group(1) for match in pattern.finditer(html))
    return extract_same_scope_urls(urls, page_url)


def classify_urls(urls: list[str], forms: list[dict], target: str) -> dict:
    buckets: dict[str, list] = defaultdict(list)
    for url in sorted(set(urls)):
        parsed = urlparse(url)
        path = parsed.path.lower()
        query_keys = set(parse_qs(parsed.query).keys())
        if any(hint in path for hint in API_HINTS):
            buckets["api_urls"].append(url)
        elif re.search(r"\.(js|css|png|jpg|svg|ico|woff2?|map)$", path):
            buckets["asset_urls"].append(url)
        else:
            buckets["page_urls"].append(url)
        if any(hint in path for hint in AUTH_HINTS):
            buckets["auth_urls"].append(url)
        if any(hint in path for hint in UPLOAD_HINTS):
            buckets["upload_urls"].append(url)
        if any(hint in path for hint in DOWNLOAD_HINTS):
            buckets["download_urls"].append(url)
        if query_keys & REDIRECT_PARAMS:
            buckets["redirect_urls"].append(url)
    for form in forms:
        buckets["forms"].append(form)
        if form["action"]:
            if form["method"] in ("POST", "PUT", "PATCH", "DELETE"):
                buckets["mutating_endpoints"].append(form["action"])
            if form["file_inputs"]:
                buckets["upload_urls"].append(form["action"])
            if form["has_password"]:
                buckets["auth_urls"].append(form["page"])
                buckets["auth_urls"].append(form["action"])
    buckets["hosts"] = sorted({urlparse(item).netloc for item in urls if scope_allows(item)})
    buckets["target"] = target
    buckets["generated_at"] = now_iso()
    for key, value in list(buckets.items()):
        if isinstance(value, list):
            if value and isinstance(value[0], dict):
                continue
            buckets[key] = sorted(set(filter(None, value)))
    return buckets


def load_seed_urls(target: str) -> list[str]:
    seed_urls = [target.rstrip("/")]
    for path in COMMON_ENDPOINTS:
        seed_urls.append(normalize_url(path, base_url=target))
    latest_crawl = latest_artifact("urls_*.txt")
    if latest_crawl and latest_crawl.exists():
        seed_urls.extend(latest_crawl.read_text(encoding="utf-8", errors="ignore").splitlines())
    discovered = latest_artifact("discovered_urls.txt")
    if discovered and discovered.exists():
        seed_urls.extend(discovered.read_text(encoding="utf-8", errors="ignore").splitlines())
    previous_inventory = load_inventory()
    seed_urls.extend(previous_inventory.get("page_urls", []))
    seed_urls.extend(previous_inventory.get("api_urls", []))
    return extract_same_scope_urls(seed_urls, target)


def build_inventory(target: str) -> tuple[dict, list[dict]]:
    client = RateLimitedHttpClient()
    urls = load_seed_urls(target)
    crawled_urls = set(urls)
    forms: list[dict] = []
    findings: list[dict] = []

    candidate_pages = [url for url in urls if not re.search(r"\.(js|css|png|jpg|svg|ico|woff2?|map)$", urlparse(url).path.lower())][:30]
    for page_url in candidate_pages:
        try:
            response = client.get(page_url, allow_redirects=True)
        except Exception:
            continue
        content_type = response.headers.get("Content-Type", "")
        if "html" not in content_type:
            continue
        html = response.text[:200000]
        page_forms = extract_form_metadata(html, page_url)
        forms.extend(page_forms)
        same_scope_urls = extract_script_urls(html, page_url)
        anchors = []
        soup = BeautifulSoup(html, "html.parser")
        for link in soup.find_all("a", href=True):
            anchors.append(link.get("href", ""))
        crawled_urls.update(extract_same_scope_urls(anchors + same_scope_urls, page_url))

    inventory = classify_urls(sorted(crawled_urls), forms, target)
    inventory["seed_count"] = len(urls)
    inventory["url_count"] = len(crawled_urls)
    inventory["form_count"] = len(forms)
    inventory["slug"] = slug(target)

    findings.append(
        build_finding(
            "F-INVENTORY-OVERVIEW",
            target,
            "Inventory fuer automatisierte Bereichstests aufgebaut",
            "Info",
            description=(
                f"Inventar enthaelt {inventory['url_count']} URLs, {len(inventory.get('api_urls', []))} API-Kandidaten, "
                f"{len(inventory.get('auth_urls', []))} Auth-Kandidaten und {inventory['form_count']} Formulare."
            ),
            evidence=json.dumps(
                {
                    "hosts": inventory.get("hosts", []),
                    "api_urls": len(inventory.get("api_urls", [])),
                    "auth_urls": len(inventory.get("auth_urls", [])),
                    "upload_urls": len(inventory.get("upload_urls", [])),
                },
                ensure_ascii=False,
            ),
        )
    )
    return inventory, findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    inventory, findings = build_inventory(target)
    save_inventory(inventory)
    payload = {
        "script": "17_inventory.py",
        "timestamp": now_iso(),
        "target": target,
        "findings": findings,
    }
    filename = write_script_output("17_inventory", payload)
    print(f"[+] Inventory gespeichert -> {filename}")
