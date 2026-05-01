from __future__ import annotations

import pandas as pd

from src.utils import setup_logging


LOGGER = setup_logging(__name__)


def build_features(data: pd.DataFrame, base_feature_columns: list[str]) -> tuple[pd.DataFrame, list[str]]:
    """Add behavior features commonly used for traffic anomaly detection."""
    features = data.copy()
    features["timestamp"] = pd.to_datetime(features["timestamp"], errors="coerce")
    features["hour"] = features["timestamp"].dt.hour.fillna(0).astype(int)
    features["minute"] = features["timestamp"].dt.minute.fillna(0).astype(int)
    features["is_business_hours"] = features["hour"].between(8, 18).astype(int)

    source_group = features.groupby("source_ip", dropna=False)
    source_port_group = features.groupby(["source_ip", "port"], dropna=False)

    features["connection_frequency"] = source_group["source_ip"].transform("count")
    features["unique_destination_count"] = source_group["destination_ip"].transform("nunique")
    features["unique_port_count"] = source_group["port"].transform("nunique")
    features["port_usage_count"] = source_port_group["port"].transform("count")
    features["avg_session_duration_by_ip"] = source_group["duration"].transform("mean")
    features["failed_attempts_by_ip"] = source_group["failed_attempts"].transform("sum")
    features["packets_per_second"] = features["packet_count"] / (features["duration"].abs() + 0.001)

    engineered_columns = [
        "hour",
        "minute",
        "is_business_hours",
        "connection_frequency",
        "unique_destination_count",
        "unique_port_count",
        "port_usage_count",
        "avg_session_duration_by_ip",
        "failed_attempts_by_ip",
        "packets_per_second",
    ]

    final_columns = base_feature_columns + engineered_columns
    LOGGER.info("Created engineered traffic features: %s", ", ".join(engineered_columns))
    return features, final_columns
