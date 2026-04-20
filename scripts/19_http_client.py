"""Kleiner CLI-Einstieg fuer den gemeinsamen HTTP-Client."""
from __future__ import annotations

import json
import sys

from auditlib import RateLimitedHttpClient, default_target, load_config, normalize_url


def inspect_target(url: str) -> dict:
    client = RateLimitedHttpClient()
    response = client.get(url, allow_redirects=True)
    return {
        "url": normalize_url(url),
        "status_code": response.status_code,
        "content_type": response.headers.get("Content-Type", ""),
        "server": response.headers.get("Server", ""),
        "final_url": str(response.url),
    }


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else default_target()
    if target == "--config":
        print(json.dumps(load_config(), indent=2, ensure_ascii=False))
    else:
        print(json.dumps(inspect_target(target), indent=2, ensure_ascii=False))
