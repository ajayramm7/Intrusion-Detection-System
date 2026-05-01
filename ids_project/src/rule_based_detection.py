from __future__ import annotations

import pandas as pd

from src.utils import setup_logging


LOGGER = setup_logging(__name__)

RESTRICTED_PORTS = {21, 23, 25, 135, 139, 445, 1433, 3306, 3389, 4444, 5900, 6667}


def run_rule_based_detection(
    data: pd.DataFrame,
    request_threshold: int = 35,
    failed_login_threshold: int = 8,
) -> pd.DataFrame:
    """Flag suspicious traffic using transparent security rules."""
    flagged = data.copy()
    reasons: list[list[str]] = [[] for _ in range(len(flagged))]

    high_request_mask = flagged["connection_frequency"] > request_threshold
    restricted_port_mask = flagged["port"].round().astype(int).isin(RESTRICTED_PORTS)
    failed_attempt_mask = flagged["failed_attempts_by_ip"] >= failed_login_threshold

    for index, matched in enumerate(high_request_mask):
        if matched:
            reasons[index].append("Too many requests from same IP")
    for index, matched in enumerate(restricted_port_mask):
        if matched:
            reasons[index].append("Access to restricted port")
    for index, matched in enumerate(failed_attempt_mask):
        if matched:
            reasons[index].append("Repeated failed login attempts")

    flagged["rule_triggered"] = ["; ".join(reason) for reason in reasons]
    flagged["rule_based_alert"] = flagged["rule_triggered"].str.len() > 0
    suspicious = flagged[flagged["rule_based_alert"]].copy()
    suspicious["detection_method"] = "rule_based"

    LOGGER.info("Rule-based detection flagged %s suspicious events", len(suspicious))
    return suspicious
