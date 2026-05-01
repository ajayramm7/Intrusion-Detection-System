from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_PATH = DATA_DIR / "network_logs.csv"
ALERTS_PATH = DATA_DIR / "detected_alerts.csv"


st.set_page_config(page_title="IDS Dashboard", layout="wide")
st.title("Intrusion Detection System Dashboard")


@st.cache_data(ttl=10)
def load_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    return pd.read_csv(path)


logs = load_csv(RAW_DATA_PATH)
alerts = load_csv(ALERTS_PATH)

if logs.empty:
    st.warning("No log data found. Run `python main.py` first.")
    st.stop()

logs["timestamp"] = pd.to_datetime(logs["timestamp"], errors="coerce")
if not alerts.empty and "timestamp" in alerts:
    alerts["timestamp"] = pd.to_datetime(alerts["timestamp"], errors="coerce")

total_logs = len(logs)
total_alerts = len(alerts)
high_alerts = int((alerts.get("severity", pd.Series(dtype=str)) == "HIGH").sum()) if not alerts.empty else 0
unique_sources = logs["source_ip"].nunique()

metric_columns = st.columns(4)
metric_columns[0].metric("Total Logs", f"{total_logs:,}")
metric_columns[1].metric("Detected Alerts", f"{total_alerts:,}")
metric_columns[2].metric("High Severity", f"{high_alerts:,}")
metric_columns[3].metric("Unique Source IPs", f"{unique_sources:,}")

st.subheader("Live Logs")
st.dataframe(logs.sort_values("timestamp", ascending=False).head(250), use_container_width=True)

st.subheader("Detected Anomalies")
if alerts.empty:
    st.info("No anomalies detected in the latest run.")
else:
    severity_filter = st.multiselect(
        "Severity",
        sorted(alerts["severity"].dropna().unique()),
        default=sorted(alerts["severity"].dropna().unique()),
    )
    filtered_alerts = alerts[alerts["severity"].isin(severity_filter)] if severity_filter else alerts
    st.dataframe(filtered_alerts.sort_values("timestamp", ascending=False), use_container_width=True)

st.subheader("Traffic Analytics")
chart_columns = st.columns(3)

with chart_columns[0]:
    st.caption("Traffic Over Time")
    traffic = logs.set_index("timestamp").resample("30min").size().rename("connections").reset_index()
    fig, ax = plt.subplots(figsize=(7, 4))
    sns.lineplot(data=traffic, x="timestamp", y="connections", ax=ax, color="#2563eb")
    ax.set_xlabel("")
    ax.set_ylabel("Connections")
    plt.xticks(rotation=35)
    st.pyplot(fig)

with chart_columns[1]:
    st.caption("Top Source IPs")
    top_ips = logs["source_ip"].value_counts().head(10).reset_index()
    top_ips.columns = ["source_ip", "connections"]
    fig, ax = plt.subplots(figsize=(7, 4))
    sns.barplot(data=top_ips, y="source_ip", x="connections", ax=ax, color="#16a34a")
    ax.set_xlabel("Connections")
    ax.set_ylabel("")
    st.pyplot(fig)

with chart_columns[2]:
    st.caption("Anomaly Count")
    if alerts.empty:
        st.bar_chart(pd.DataFrame({"count": [0]}, index=["None"]))
    else:
        anomaly_counts = alerts["severity"].value_counts().reindex(["LOW", "MEDIUM", "HIGH"]).fillna(0)
        st.bar_chart(anomaly_counts)
