"""Erzeugt und verwaltet einen isolierten Audit-Run."""
from __future__ import annotations

import json
import sys

from auditlib import current_run_meta, default_target, start_run


def main() -> None:
    command = sys.argv[1] if len(sys.argv) > 1 else "show"
    target = sys.argv[2] if len(sys.argv) > 2 else default_target()
    if command == "start":
        metadata = start_run(target)
        print(json.dumps(metadata, ensure_ascii=False))
        return
    print(json.dumps(current_run_meta(), ensure_ascii=False))


if __name__ == "__main__":
    main()
