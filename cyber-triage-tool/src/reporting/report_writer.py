from __future__ import annotations
from pathlib import Path
import json
from datetime import datetime


def ensure_case_dir(base: Path | str, case_id: str | None, prefix: str = "CASE") -> Path:
    base_path = Path(base)
    base_path.mkdir(parents=True, exist_ok=True)
    if not case_id:
        case_id = f"{prefix}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    case_dir = base_path / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    return case_dir


def write_json(path: Path | str, data: dict | list) -> None:
    p = Path(path)
    with p.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def write_html(path: Path | str, summary: dict, items: list[dict]) -> None:
    p = Path(path)
    html = [
        "<html><head><meta charset='utf-8'><title>Cyber Triage Report</title>",
        "<style>body{font-family:Segoe UI,Arial,sans-serif} table{border-collapse:collapse} td,th{border:1px solid #ddd;padding:6px}</style>",
        "</head><body>",
        "<h1>Cyber Triage Report</h1>",
        f"<p><strong>Case:</strong> {summary.get('case_id','N/A')} | <strong>When:</strong> {summary.get('generated_at','')} | <strong>Target:</strong> {summary.get('target','')}</p>",
        "<h2>Findings</h2>",
        "<table>",
        "<tr><th>Path</th><th>SHA256</th><th>Entropy</th><th>Flags</th><th>YARA</th><th>PE</th></tr>",
    ]
    for it in items:
        html.append(
            "<tr>"
            f"<td>{it.get('path','')}</td>"
            f"<td>{(it.get('hashes') or {}).get('sha256','')}</td>"
            f"<td>{it.get('entropy','')}</td>"
            f"<td>{', '.join(it.get('flags', []))}</td>"
            f"<td>{', '.join(it.get('yara_matches', []))}</td>"
            f"<td>{(it.get('pe_info') or {}).get('imphash','')}</td>"
            "</tr>"
        )
    html.extend(["</table>", "</body></html>"])
    p.write_text("\n".join(html), encoding="utf-8")

