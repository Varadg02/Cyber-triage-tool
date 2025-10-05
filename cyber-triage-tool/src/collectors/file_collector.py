from pathlib import Path
from typing import List
import logging

logger = logging.getLogger(__name__)


class FileCollector:
    def __init__(self, max_file_size_mb: int = 50, follow_symlinks: bool = False):
        self.max_bytes = int(max_file_size_mb) * 1024 * 1024
        self.follow_symlinks = follow_symlinks

    def collect(self, root: str | Path) -> List[Path]:
        root = Path(root)
        if not root.exists():
            logger.error(f"Path not found: {root}")
            return []

        files: List[Path] = []
        for p in root.rglob("*"):
            try:
                if not p.is_file():
                    continue
                if p.is_symlink() and not self.follow_symlinks:
                    continue
                st = p.stat()
                if st.st_size <= self.max_bytes:
                    files.append(p)
            except Exception as e:
                logger.debug(f"Skipping {p}: {e}")
                continue
        return files

