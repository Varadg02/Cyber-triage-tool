from __future__ import annotations
from collections import Counter
from math import log2
from pathlib import Path


def _entropy_from_counter(counter: Counter) -> float:
    total = sum(counter.values())
    if total == 0:
        return 0.0
    ent = 0.0
    for count in counter.values():
        p = count / total
        ent -= p * log2(p)
    return ent


def analyze_file(path: str | Path, chunk_size: int = 1024 * 1024) -> dict:
    p = Path(path)
    counts = Counter()
    try:
        with p.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                counts.update(chunk)
        return {"entropy": round(_entropy_from_counter(counts), 4)}
    except Exception as e:
        return {"entropy_error": str(e)}

