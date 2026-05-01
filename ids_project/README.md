# Python Intrusion Detection System

Production-style Intrusion Detection System (IDS) project that detects abnormal traffic from network logs using both transparent security rules and machine learning anomaly detection.

## Overview

The project loads network connection logs, cleans and enriches them, runs rule-based detection, trains an Isolation Forest on normal traffic, merges alerts, writes audit logs, and provides a Streamlit dashboard for analysis.

Synthetic KDD/CICIDS-style traffic is generated automatically when `data/network_logs.csv` does not exist, so the project runs out of the box.

## Architecture

```text
Raw CSV Logs
    |
    v
data_preprocessing.py
    |-- missing values
    |-- categorical encoding
    |-- numerical scaling
    v
feature_engineering.py
    |-- connection frequency
    |-- port usage
    |-- duration statistics
    |-- failed attempt counts
    v
+--------------------------+
|                          |
v                          v
rule_based_detection.py    anomaly_detection.py
    |                          |
    v                          v
Rule Alerts               ML Anomalies
    \                          /
     \                        /
      v                      v
        alert_system.py -> logs/alerts.log
              |
              v
        dashboard/app.py
```

## Project Structure

```text
ids_project/
  data/
  models/
  logs/
  src/
    data_preprocessing.py
    feature_engineering.py
    rule_based_detection.py
    anomaly_detection.py
    alert_system.py
    utils.py
  dashboard/
    app.py
  main.py
  requirements.txt
  README.md
```

## How To Run

```bash
cd ids_project
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py --retrain
```

Launch the dashboard:

```bash
streamlit run dashboard/app.py
```

Or run the pipeline and launch the dashboard in one command:

```bash
python main.py --dashboard
```

## Data Fields

The generated dataset contains:

- `source_ip`
- `destination_ip`
- `port`
- `protocol`
- `packet_count`
- `duration`
- `timestamp`
- `failed_attempts`
- `label`

## Detection Logic

Rule-based detection flags:

- Too many requests from the same source IP
- Access to restricted or commonly abused ports
- Repeated failed login attempts

Machine learning detection:

- Uses `IsolationForest`
- Trains on records labeled `normal`
- Scores all traffic
- Saves the model to `models/isolation_forest_model.joblib`

## Sample Output

```text
2026-04-29 23:05:11 | WARNING | HIGH | rule_based+machine_learning | 203.0.113.12 -> 172.16.0.4:3389 | Access to restricted port; Repeated failed login attempts
2026-04-29 23:05:11 | WARNING | MEDIUM | rule_based | 10.0.1.14 -> 172.16.0.20:80 | Too many requests from same IP
```

Pipeline artifacts:

- `data/network_logs.csv`
- `data/processed_features.csv`
- `data/rule_based_alerts.csv`
- `data/ml_anomalies.csv`
- `data/detected_alerts.csv`
- `models/isolation_forest_model.joblib`
- `logs/alerts.log`
- `logs/ids_app.log`

## Future Improvements

- Add live packet capture from Zeek, Suricata, or NetFlow exporters
- Add supervised classifiers when labeled enterprise data is available
- Add alert deduplication windows and incident ticket integrations
- Add authentication and role-based access to the dashboard
- Store alerts in PostgreSQL or Elasticsearch for long-term search
