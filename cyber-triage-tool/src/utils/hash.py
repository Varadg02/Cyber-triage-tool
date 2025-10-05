from __future__ import annotations
from pathlib import Path
import hashlib
from typing import Iterable


def compute_hashes(path: Path | str, algorithms: Iterable[str] = ("sha256", "md5", "sha1")) -> dict:
    p = Path(path)
    algos = {name.lower(): hashlib.new(name.lower()) for name in algorithms}

    try:
        with p.open("rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                for h in algos.values():
                    h.update(chunk)
        return {name: h.hexdigest() for name, h in algos.items()}
    except Exception as e:
        return {"error": str(e)}

