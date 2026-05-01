from __future__ import annotations

import argparse
import subprocess
import sys

import pandas as pd

from src.alert_system import emit_alerts
from src.anomaly_detection import predict_anomalies
from src.data_preprocessing import load_logs, preprocess_logs
from src.feature_engineering import build_features
from src.rule_based_detection import run_rule_based_detection
from src.utils import (
    MERGED_ALERTS_PATH,
    ML_ALERTS_PATH,
    PROCESSED_DATA_PATH,
    RAW_DATA_PATH,
    RULE_ALERTS_PATH,
    ensure_directories,
    setup_logging,
)


LOGGER = setup_logging("ids.main")


def merge_detection_results(rule_alerts: pd.DataFrame, ml_alerts: pd.DataFrame) -> pd.DataFrame:
    """Merge rule and ML alerts without duplicating identical log rows."""
    if rule_alerts.empty and ml_alerts.empty:
        return pd.DataFrame()

    combined = pd.concat([rule_alerts, ml_alerts], ignore_index=True, sort=False)
    identity_columns = ["timestamp", "source_ip", "destination_ip", "port", "protocol"]
    grouped = combined.groupby(identity_columns, dropna=False, as_index=False).agg(
        {
            "packet_count": "first",
            "duration": "first",
            "failed_attempts": "first",
            "label": "first",
            "connection_frequency": "first",
            "failed_attempts_by_ip": "first",
            "rule_triggered": lambda values: "; ".join(sorted({str(value) for value in values if str(value) != "nan" and value})),
            "anomaly_score": "min",
            "detection_method": lambda values: "+".join(sorted(set(values))),
        }
    )
    return grouped


def run_pipeline(retrain: bool = False) -> pd.DataFrame:
    """Execute the full IDS detection pipeline."""
    ensure_directories()
    logs = load_logs(RAW_DATA_PATH)
    preprocessed, base_feature_columns = preprocess_logs(logs, fit=True)
    featured, feature_columns = build_features(preprocessed, base_feature_columns)
    featured.to_csv(PROCESSED_DATA_PATH, index=False)

    rule_alerts = run_rule_based_detection(featured)
    ml_alerts = predict_anomalies(featured, feature_columns, retrain=retrain)

    rule_alerts.to_csv(RULE_ALERTS_PATH, index=False)
    ml_alerts.to_csv(ML_ALERTS_PATH, index=False)

    merged_alerts = merge_detection_results(rule_alerts, ml_alerts)
    alerted = emit_alerts(merged_alerts)
    alerted.to_csv(MERGED_ALERTS_PATH, index=False)

    LOGGER.info("Pipeline complete. Alerts saved to %s", MERGED_ALERTS_PATH)
    return alerted


def launch_dashboard() -> None:
    """Launch the Streamlit dashboard as a subprocess."""
    dashboard_path = "dashboard/app.py"
    subprocess.run([sys.executable, "-m", "streamlit", "run", dashboard_path], check=False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Python IDS detection pipeline.")
    parser.add_argument("--retrain", action="store_true", help="Retrain the anomaly detection model.")
    parser.add_argument("--dashboard", action="store_true", help="Launch the Streamlit dashboard after processing.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_pipeline(retrain=args.retrain)
    if args.dashboard:
        launch_dashboard()
