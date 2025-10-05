import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def setup_logging(level: str = "INFO", log_file: str | None = None):
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, level.upper(), logging.INFO))
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    ch.setFormatter(formatter)

    # Avoid duplicate handlers if reinitialized
    logger.handlers.clear()
    logger.addHandler(ch)

    # Optional file handler
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(log_file, maxBytes=5_000_000, backupCount=3)
        fh.setLevel(getattr(logging, level.upper(), logging.INFO))
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger

