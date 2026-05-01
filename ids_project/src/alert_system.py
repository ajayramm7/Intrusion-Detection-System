from __future__ import annotations

import logging

import pandas as pd

from src.utils import ALERT_LOG_PATH, setup_logging


LOGGER = setup_logging(__name__)


def categorize_severity(row: pd.Series) -> str:
    """Assign alert severity from rule and ML signals."""
    reasons = str(row.get("rule_triggered", ""))
    failed_attempts = float(row.get("failed_attempts_by_ip", 0))
    packet_count = float(row.get("packet_count", 0))
    anomaly_score = float(row.get("anomaly_score", 0))

    if "Access to restricted port" in reasons and failed_attempts >= 15:
        return "HIGH"
    if "Repeated failed login attempts" in reasons or anomaly_score < -0.08:
        return "HIGH"
    if "Too many requests" in reasons or packet_count > 500:
        return "MEDIUM"
    return "LOW"


def emit_alerts(alerts: pd.DataFrame) -> pd.DataFrame:
    """Log alerts to console and to the dedicated alert log file."""
    if alerts.empty:
        LOGGER.info("No alerts generated in this run")
        return alerts

    enriched = alerts.copy()
    enriched["severity"] = enriched.apply(categorize_severity, axis=1)

    alert_logger = logging.getLogger("ids.alerts")
    alert_logger.setLevel(logging.INFO)
    alert_logger.propagate = False

    if not alert_logger.handlers:
        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        file_handler = logging.FileHandler(ALERT_LOG_PATH, encoding="utf-8")
        file_handler.setFormatter(formatter)
        alert_logger.addHandler(file_handler)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        alert_logger.addHandler(console_handler)

    for _, row in enriched.iterrows():
        message = (
            f"{row['severity']} | {row.get('detection_method', 'combined')} | "
            f"{row.get('source_ip')} -> {row.get('destination_ip')}:{row.get('port')} | "
            f"{row.get('rule_triggered', 'ML anomaly')}"
        )
        alert_logger.warning(message)

    LOGGER.info("Emitted %s alerts", len(enriched))
    return enriched
