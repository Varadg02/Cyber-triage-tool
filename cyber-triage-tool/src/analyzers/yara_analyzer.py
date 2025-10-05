from __future__ import annotations
from pathlib import Path
from typing import List

try:
    import yara  # type: ignore
except Exception:  # pragma: no cover
    yara = None


def _compile_rules(rule_dir: Path):
    if yara is None:
        return None
    if not rule_dir.exists():
        return None
    filepaths = {}
    for p in rule_dir.glob("**/*.yar*"):
        filepaths[p.stem] = str(p)
    if not filepaths:
        return None
    try:
        return yara.compile(filepaths=filepaths)
    except Exception:
        return None


def scan_file(path: str | Path, rules_dir: str | Path) -> List[str]:
    if yara is None:
        return []
    rules = _compile_rules(Path(rules_dir))
    if rules is None:
        return []
    try:
        matches = rules.match(str(path))
        return [m.rule for m in matches] if matches else []
    except Exception:
        return []

