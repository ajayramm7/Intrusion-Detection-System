from __future__ import annotations

import logging
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"
LOGS_DIR = PROJECT_ROOT / "logs"
DASHBOARD_DIR = PROJECT_ROOT / "dashboard"

RAW_DATA_PATH = DATA_DIR / "network_logs.csv"
PROCESSED_DATA_PATH = DATA_DIR / "processed_features.csv"
RULE_ALERTS_PATH = DATA_DIR / "rule_based_alerts.csv"
ML_ALERTS_PATH = DATA_DIR / "ml_anomalies.csv"
MERGED_ALERTS_PATH = DATA_DIR / "detected_alerts.csv"
MODEL_PATH = MODELS_DIR / "isolation_forest_model.joblib"
SCALER_PATH = MODELS_DIR / "feature_scaler.joblib"
ENCODER_PATH = MODELS_DIR / "categorical_encoder.joblib"
ALERT_LOG_PATH = LOGS_DIR / "alerts.log"
APP_LOG_PATH = LOGS_DIR / "ids_app.log"


def ensure_directories() -> None:
    """Create required project folders if they do not already exist."""
    for directory in (DATA_DIR, MODELS_DIR, LOGS_DIR, DASHBOARD_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def setup_logging(name: str = "ids") -> logging.Logger:
    """Configure reusable console and file logging."""
    ensure_directories()
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    file_handler = logging.FileHandler(APP_LOG_PATH, encoding="utf-8")
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return logger


def ip_to_int(ip_address: str) -> int:
    """Convert dotted IPv4 addresses to stable numeric values."""
    try:
        parts = [int(part) for part in str(ip_address).split(".")]
        if len(parts) != 4 or any(part < 0 or part > 255 for part in parts):
            return 0
        return (
            (parts[0] << 24)
            + (parts[1] << 16)
            + (parts[2] << 8)
            + parts[3]
        )
    except (TypeError, ValueError):
        return 0
