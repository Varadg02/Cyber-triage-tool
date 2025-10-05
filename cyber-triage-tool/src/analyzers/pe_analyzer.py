from __future__ import annotations
from pathlib import Path

try:
    import pefile  # type: ignore
except Exception:  # pragma: no cover
    pefile = None


def analyze_file(path: str | Path) -> dict:
    p = Path(path)
    ext = p.suffix.lower()
    if ext not in {".exe", ".dll", ".sys", ".ocx"}:
        return {"is_pe": False}

    if pefile is None:
        return {"is_pe": True, "pe_analysis": "skipped (pefile not installed)"}

    try:
        pe = pefile.PE(str(p), fast_load=True)
        # Avoid expensive loads; basic info only
        info = {
            "is_pe": True,
            "num_sections": len(pe.sections) if hasattr(pe, "sections") else None,
        }
        try:
            if hasattr(pe, "get_imphash"):
                info["imphash"] = pe.get_imphash()  # type: ignore[attr-defined]
        except Exception:
            pass
        try:
            ts = pe.FILE_HEADER.TimeDateStamp  # type: ignore[attr-defined]
            info["timestamp"] = int(ts)
        except Exception:
            pass
        return info
    except Exception as e:
        return {"is_pe": True, "pe_error": str(e)}

