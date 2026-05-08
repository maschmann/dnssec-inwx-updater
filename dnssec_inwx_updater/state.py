from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path


def load_state(path: Path | str) -> dict:
    path = Path(path)
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def save_state(path: Path | str, cert_hash: str, timestamp: datetime) -> None:
    path = Path(path)
    data = {
        "last_cert_hash": cert_hash,
        "last_updated": timestamp.isoformat(),
    }
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.replace(tmp, path)
