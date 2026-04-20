"""Setzt/normalisiert ein Ziel in config.json.allowed_targets[0]."""
import json
import pathlib
import sys
from urllib.parse import urlparse


def normalize_target(raw_target):
    target = raw_target.strip()
    if not target:
        raise ValueError("Leere URL ist nicht erlaubt.")
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Ungültige URL. Erwartet wird http(s)://host")
    normalized = f"{parsed.scheme}://{parsed.netloc}"
    return normalized.rstrip("/")


def main():
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python scripts/00_prepare_target.py <url>")

    config_path = pathlib.Path("config.json")
    if not config_path.exists():
        example_path = pathlib.Path("config.example.json")
        if not example_path.exists():
            raise SystemExit("config.json und config.example.json nicht gefunden.")
        config_path.write_text(example_path.read_text(encoding="utf-8"), encoding="utf-8")

    target = normalize_target(sys.argv[1])
    config = json.loads(config_path.read_text(encoding="utf-8"))
    existing = [item for item in config.get("allowed_targets", []) if item != target]
    config["allowed_targets"] = [target] + existing
    config_path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(target)


if __name__ == "__main__":
    main()
