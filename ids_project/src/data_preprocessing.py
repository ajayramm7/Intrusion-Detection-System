from __future__ import annotations

import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from src.utils import ENCODER_PATH, RAW_DATA_PATH, SCALER_PATH, ip_to_int, setup_logging


LOGGER = setup_logging(__name__)

REQUIRED_COLUMNS = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "port",
    "protocol",
    "packet_count",
    "duration",
    "failed_attempts",
    "label",
]


def generate_synthetic_logs(output_path: Path = RAW_DATA_PATH, rows: int = 2500) -> pd.DataFrame:
    """Generate realistic IDS-style network logs with a small anomaly population."""
    rng = np.random.default_rng(42)
    timestamps = pd.date_range("2026-04-01", periods=rows, freq="min")
    normal_sources = [f"10.0.{i // 255}.{i % 255 + 1}" for i in range(1, 420)]
    destinations = [f"172.16.{i // 255}.{i % 255 + 1}" for i in range(1, 80)]
    protocols = np.array(["TCP", "UDP", "ICMP"])

    data = pd.DataFrame(
        {
            "timestamp": timestamps,
            "source_ip": rng.choice(normal_sources, rows),
            "destination_ip": rng.choice(destinations, rows),
            "port": rng.choice([22, 53, 80, 123, 443, 3306, 8080], rows, p=[0.05, 0.16, 0.32, 0.06, 0.31, 0.03, 0.07]),
            "protocol": rng.choice(protocols, rows, p=[0.68, 0.27, 0.05]),
            "packet_count": rng.poisson(35, rows) + 1,
            "duration": np.round(rng.gamma(shape=2.0, scale=3.0, size=rows), 3),
            "failed_attempts": rng.poisson(0.15, rows),
            "label": "normal",
        }
    )

    anomaly_count = max(80, rows // 12)
    anomaly_indexes = rng.choice(data.index, anomaly_count, replace=False)
    scanner_ips = [f"203.0.113.{i}" for i in range(10, 35)]

    data.loc[anomaly_indexes, "source_ip"] = rng.choice(scanner_ips, anomaly_count)
    data.loc[anomaly_indexes, "port"] = rng.choice([21, 23, 25, 3389, 4444, 5900, 6667], anomaly_count)
    data.loc[anomaly_indexes, "packet_count"] = rng.integers(250, 1800, anomaly_count)
    data.loc[anomaly_indexes, "duration"] = np.round(rng.uniform(0.05, 1.2, anomaly_count), 3)
    data.loc[anomaly_indexes, "failed_attempts"] = rng.integers(8, 65, anomaly_count)
    data.loc[anomaly_indexes, "label"] = "attack"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    data.to_csv(output_path, index=False)
    LOGGER.info("Generated synthetic network dataset at %s with %s rows", output_path, len(data))
    return data


def load_logs(path: Path = RAW_DATA_PATH) -> pd.DataFrame:
    """Load network logs, generating a synthetic dataset when none exists."""
    if not path.exists():
        return generate_synthetic_logs(path)

    data = pd.read_csv(path)
    missing = sorted(set(REQUIRED_COLUMNS) - set(data.columns))
    if missing:
        raise ValueError(f"Dataset is missing required columns: {missing}")

    LOGGER.info("Loaded %s network log rows from %s", len(data), path)
    return data


def preprocess_logs(data: pd.DataFrame, fit: bool = True) -> tuple[pd.DataFrame, list[str]]:
    """Clean, encode, and normalize raw network log data."""
    clean = data.copy()
    clean["timestamp"] = pd.to_datetime(clean["timestamp"], errors="coerce")
    clean["timestamp"] = clean["timestamp"].fillna(clean["timestamp"].median())

    clean["source_ip"] = clean["source_ip"].fillna("0.0.0.0")
    clean["destination_ip"] = clean["destination_ip"].fillna("0.0.0.0")
    clean["protocol"] = clean["protocol"].fillna("UNKNOWN").str.upper()
    clean["label"] = clean.get("label", "unknown").fillna("unknown")

    for column in ["port", "packet_count", "duration", "failed_attempts"]:
        clean[column] = pd.to_numeric(clean[column], errors="coerce")
        clean[column] = clean[column].fillna(clean[column].median())
        lower, upper = clean[column].quantile([0.01, 0.99])
        clean[column] = clean[column].clip(lower=lower, upper=upper)

    clean["source_ip_encoded"] = clean["source_ip"].apply(ip_to_int)
    clean["destination_ip_encoded"] = clean["destination_ip"].apply(ip_to_int)
    protocol_dummies = pd.get_dummies(clean["protocol"], prefix="protocol", dtype=int)
    encoded = pd.concat([clean, protocol_dummies], axis=1)

    numeric_source_columns = [
        "port",
        "packet_count",
        "duration",
        "failed_attempts",
        "source_ip_encoded",
        "destination_ip_encoded",
    ]
    scaled_feature_columns = [f"{column}_scaled" for column in numeric_source_columns]
    feature_columns = scaled_feature_columns + protocol_dummies.columns.tolist()

    if fit:
        scaler = StandardScaler()
        encoded[scaled_feature_columns] = scaler.fit_transform(encoded[numeric_source_columns])
        with SCALER_PATH.open("wb") as scaler_file:
            pickle.dump(scaler, scaler_file)
        with ENCODER_PATH.open("wb") as encoder_file:
            pickle.dump(feature_columns, encoder_file)
    else:
        with SCALER_PATH.open("rb") as scaler_file:
            scaler = pickle.load(scaler_file)
        with ENCODER_PATH.open("rb") as encoder_file:
            feature_columns = pickle.load(encoder_file)
        for column in feature_columns:
            if column not in encoded.columns:
                encoded[column] = 0
        encoded[scaled_feature_columns] = scaler.transform(encoded[numeric_source_columns])

    LOGGER.info("Preprocessed logs into %s ML-ready features", len(feature_columns))
    return encoded, feature_columns
