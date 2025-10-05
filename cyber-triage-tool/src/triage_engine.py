from __future__ import annotations
from pathlib import Path
from datetime import datetime
import logging

from .collectors.file_collector import FileCollector
from .utils.hash import compute_hashes
from .analyzers.entropy_analyzer import analyze_file as entropy_analyze
from .analyzers.pe_analyzer import analyze_file as pe_analyze
from .analyzers.yara_analyzer import scan_file as yara_scan
from .reporting.report_writer import ensure_case_dir, write_json, write_html

logger = logging.getLogger(__name__)


class TriageEngine:
    def __init__(self, config: dict, output_dir: str):
        self.config = config or {}
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _new_case_dir(self, case_id: str | None) -> Path:
        prefix = (
            self.config.get("investigation", {})
            .get("default_case_prefix", "CASE")
        )
        return ensure_case_dir(self.output_dir, case_id, prefix)

    def _yara_rules_dir(self) -> Path | None:
        rules_dir = (
            self.config.get("triage", {})
            .get("quick_scan", {})
            .get("yara_rules_dir")
        )
        if rules_dir:
            p = Path(rules_dir)
            return p if p.exists() else None
        return None

    def quick_scan(self, path: str, case_id: str | None = None) -> Path:
        target = Path(path)
        case_dir = self._new_case_dir(case_id)
        logger.info(f"[Quick Scan] Target: {target} -> Case dir: {case_dir}")

        max_mb = (
            self.config.get("triage", {})
            .get("quick_scan", {})
            .get("max_file_size_mb", 50)
        )
        collector = FileCollector(max_file_size_mb=max_mb)
        files = collector.collect(target)
        logger.info(f"Collected {len(files)} files (<= {max_mb} MB)")

        yara_dir = self._yara_rules_dir()

        items = []
        for fp in files:
            record: dict = {"path": str(fp), "flags": []}
            # Hashes
            record["hashes"] = compute_hashes(fp, ("sha256",))
            # Entropy
            ent = entropy_analyze(fp)
            record.update(ent)
            if isinstance(ent.get("entropy"), (int, float)) and ent["entropy"] >= 7.5:
                record["flags"].append("high_entropy")
            # PE info
            record["pe_info"] = pe_analyze(fp)
            if record["pe_info"].get("is_pe"):
                record["flags"].append("executable")
            # YARA
            if yara_dir is not None:
                record["yara_matches"] = yara_scan(fp, yara_dir)
                if record["yara_matches"]:
                    record["flags"].append("yara_match")
            else:
                record["yara_matches"] = []

            items.append(record)

        summary = {
            "case_id": case_dir.name,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "target": str(target),
            "count": len(items),
        }

        write_json(case_dir / "report.json", {"summary": summary, "items": items})
        write_html(case_dir / "report.html", summary, items)
        logger.info(f"Report written to {case_dir}")
        return case_dir

    def full_analysis(self, target: str, case_id: str | None):
        # Placeholder: could incorporate memory forensics, registry, EVTX, network, etc.
        logger.info(f"[Full Analysis] Target: {target} Case: {case_id}")
        return self.quick_scan(target, case_id)

    def investigate(self, case_id: str):
        # Placeholder: load case artifacts and provide workflow
        logger.info(f"[Investigate] Case: {case_id}")

    def start_web_interface(self):
        # Placeholder: to be implemented using Flask app in src.web
        logger.info("Starting web interface (stub)")

    def interactive_mode(self):
        logger.info("Interactive mode (stub). Use --help to see options.")

