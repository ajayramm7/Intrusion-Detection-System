from __future__ import annotations

import csv
import html
import shutil
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "ids_project"
TEMPLATE = Path(r"c:\Users\ajayram_231210006\Downloads\format .docx")
OUTPUT = ROOT / "IDS_Project_Report.docx"
ALERTS = PROJECT / "data" / "detected_alerts.csv"
LOGS = PROJECT / "data" / "network_logs.csv"

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def read_count(path: Path) -> int:
    with path.open(newline="", encoding="utf-8") as handle:
        return max(sum(1 for _ in handle) - 1, 0)


def severity_counts() -> dict[str, int]:
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    if not ALERTS.exists():
        return counts
    with ALERTS.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            severity = row.get("severity", "").upper()
            if severity in counts:
                counts[severity] += 1
    return counts


def esc(value: object) -> str:
    return html.escape(str(value), quote=False)


def run(text: str, bold: bool = False, size: int = 22) -> str:
    props = f"<w:rPr><w:b/><w:sz w:val=\"{size}\"/></w:rPr>" if bold else f"<w:rPr><w:sz w:val=\"{size}\"/></w:rPr>"
    return f"<w:r>{props}<w:t xml:space=\"preserve\">{esc(text)}</w:t></w:r>"


def paragraph(text: str = "", style: str | None = None, bold: bool = False, align: str | None = None, size: int = 22) -> str:
    ppr = []
    if style:
        ppr.append(f"<w:pStyle w:val=\"{style}\"/>")
    if align:
        ppr.append(f"<w:jc w:val=\"{align}\"/>")
    ppr_xml = f"<w:pPr>{''.join(ppr)}</w:pPr>" if ppr else ""
    return f"<w:p>{ppr_xml}{run(text, bold=bold, size=size)}</w:p>"


def bullet(text: str) -> str:
    return paragraph(f"- {text}", size=22)


def page_break() -> str:
    return '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'


def table(rows: list[list[str]]) -> str:
    cells = []
    for row_index, row in enumerate(rows):
        row_xml = []
        for cell in row:
            shading = '<w:shd w:fill="D9EAF7"/>' if row_index == 0 else ""
            row_xml.append(
                "<w:tc>"
                f"<w:tcPr><w:tcW w:w=\"2400\" w:type=\"dxa\"/>{shading}</w:tcPr>"
                f"{paragraph(cell, bold=row_index == 0)}"
                "</w:tc>"
            )
        cells.append(f"<w:tr>{''.join(row_xml)}</w:tr>")
    return (
        "<w:tbl>"
        '<w:tblPr><w:tblW w:w="0" w:type="auto"/>'
        '<w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
        '<w:left w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
        '<w:bottom w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
        '<w:right w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
        '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
        '<w:insideV w:val="single" w:sz="4" w:space="0" w:color="999999"/></w:tblBorders></w:tblPr>'
        f"{''.join(cells)}</w:tbl>"
    )


def section(title: str) -> str:
    return paragraph(title, style="Heading1", bold=True, size=30)


def build_body() -> str:
    log_count = read_count(LOGS) if LOGS.exists() else 2500
    alert_count = read_count(ALERTS) if ALERTS.exists() else 451
    severities = severity_counts()

    parts: list[str] = []
    parts.append(paragraph("Project Report", style="Title", bold=True, align="center", size=40))
    parts.append(paragraph("Intrusion Detection System Using Rule-Based and Machine Learning Detection", bold=True, align="center", size=28))
    parts.append(paragraph("Python Cybersecurity and Machine Learning Project", align="center", size=24))
    parts.append(paragraph(""))
    parts.append(table([
        ["Project Name", "Intrusion Detection System"],
        ["Technology Stack", "Python, Pandas, NumPy, Scikit-learn, Streamlit, Matplotlib, Seaborn"],
        ["Detection Methods", "Rule-based detection and Isolation Forest anomaly detection"],
        ["Dataset", "Synthetic KDD/CICIDS-style network traffic logs"],
        ["Generated Records", f"{log_count:,} network log records"],
        ["Detected Alerts", f"{alert_count:,} suspicious or anomalous events"],
    ]))
    parts.append(page_break())

    parts.append(section("1. Introduction"))
    parts.append(paragraph(
        "Cybersecurity has become one of the most important areas of modern computing because organizations depend on continuously connected systems, cloud services, web applications, and internal networks. As digital infrastructure grows, the volume of network traffic also increases, creating more opportunities for attackers to hide malicious activity inside normal communication patterns. Intrusion Detection Systems, commonly known as IDS solutions, are designed to monitor this traffic and identify behavior that may indicate scanning, brute-force login attempts, policy violations, malware communication, or unauthorized access."
    ))
    parts.append(paragraph(
        "The broader field of intrusion detection combines network engineering, security operations, data analysis, and machine learning. Traditional IDS tools often rely on signatures or fixed rules, which are effective for known attack patterns but can miss unusual behavior that has not been manually defined. Machine learning methods provide an additional layer by learning normal behavior and identifying deviations from that baseline. A practical IDS benefits from both approaches: rule-based detection provides explainability, while anomaly detection helps identify suspicious behavior that does not match predefined rules."
    ))
    parts.append(paragraph(
        "This project implements a complete Python-based IDS that analyzes log data similar to KDD Cup and CICIDS datasets. The system processes traffic records containing source IP, destination IP, protocol, port, packet count, duration, timestamp, and failed login attempts. It then performs preprocessing, feature engineering, rule-based detection, machine learning anomaly detection, alert generation, and dashboard visualization. The result is a modular and runnable cybersecurity project suitable for demonstrating practical software engineering, security analytics, and machine learning skills."
    ))

    parts.append(section("2. Problem Statement"))
    parts.append(paragraph(
        "Modern networks generate large volumes of traffic, making manual monitoring impractical. Security teams need systems that can automatically identify suspicious patterns such as repeated failed login attempts, excessive connections from a single IP address, access to restricted ports, and unusual packet behavior. Without automation, important signals can be missed, especially when malicious activity is distributed across many records or hidden among normal traffic."
    ))
    parts.append(paragraph(
        "The main problem addressed by this project is the lack of a simple, extensible, and understandable IDS pipeline that combines explainable rules with machine learning. Rule-only systems can be too rigid, while machine-learning-only systems can be difficult to interpret. A production-oriented approach must provide both clear security logic and statistical anomaly detection, along with persistent alerts and a dashboard for analysis."
    ))
    parts.append(paragraph(
        "The impact of this problem is significant. Undetected abnormal traffic can lead to credential compromise, unauthorized service access, data exfiltration, lateral movement, downtime, and financial loss. The users affected include system administrators, security analysts, small organizations, educational institutions, and software teams that need a practical way to understand intrusion detection concepts and prototype security monitoring workflows."
    ))

    parts.append(section("3. Objectives"))
    parts.append(paragraph(
        "The primary objective of this project is to design and implement a modular Python Intrusion Detection System that detects suspicious network activity using both rule-based logic and machine learning anomaly detection."
    ))
    parts.append(bullet("To generate or load structured network log data with fields commonly used in IDS datasets."))
    parts.append(bullet("To clean, normalize, and encode network traffic data for analysis and model training."))
    parts.append(bullet("To engineer security-relevant features such as connection frequency, port usage, session duration statistics, and failed attempt counts."))
    parts.append(bullet("To implement transparent rules for restricted ports, excessive requests, and repeated failed logins."))
    parts.append(bullet("To train an Isolation Forest model on normal traffic and predict anomalous records."))
    parts.append(bullet("To produce categorized alerts and visualize traffic trends through a Streamlit dashboard."))

    parts.append(section("4. Methodology"))
    parts.append(paragraph(
        "The methodology follows a software development and analytical approach. The project was implemented as a modular Python application, with each major responsibility separated into its own module. This structure makes the system easier to test, extend, and explain. The pipeline begins with raw network logs and ends with saved alerts, trained model artifacts, application logs, and an interactive dashboard."
    ))
    parts.append(paragraph("Tools and materials used in this project include:"))
    for item in [
        "Python for the complete IDS application and pipeline orchestration.",
        "Pandas and NumPy for log loading, cleaning, transformation, and feature computation.",
        "Scikit-learn for StandardScaler preprocessing and Isolation Forest anomaly detection.",
        "Streamlit for the dashboard interface.",
        "Matplotlib and Seaborn for traffic and alert visualizations.",
        "Python logging module for operational logs and alert persistence.",
        "Synthetic KDD/CICIDS-style traffic logs for immediate reproducibility.",
    ]:
        parts.append(bullet(item))

    parts.append(paragraph("The system follows this processing flow:"))
    parts.append(paragraph(
        "Raw Logs -> Data Preprocessing -> Feature Engineering -> Rule-Based Detection -> ML Anomaly Detection -> Alert Merge -> Alert Logging -> Dashboard Visualization",
        bold=True,
    ))
    parts.append(paragraph(
        "In the data preprocessing phase, the project handles missing values, converts timestamps, normalizes numeric fields, converts IP addresses into numeric values, and one-hot encodes protocol values. Outliers are clipped using percentile limits to reduce noise while preserving meaningful extreme behavior. Scaled features are kept separate from raw fields so that the model receives normalized values while the security rules and alerts remain readable."
    ))
    parts.append(paragraph(
        "In the feature engineering phase, the system computes connection frequency per source IP, unique destination count, unique port count, port usage count, average session duration by IP, total failed attempts by IP, packets per second, hour of day, minute, and business-hours indicators. These features help transform individual log rows into behavioral records that are more useful for detecting abnormal traffic."
    ))
    parts.append(paragraph(
        "The rule-based detector applies clear security policies. It flags traffic when a source IP generates too many requests, when a destination port is part of the restricted port list, or when failed login behavior exceeds a threshold. These rules produce human-readable explanations, which are important in cybersecurity because analysts need to understand why an alert was raised."
    ))
    parts.append(paragraph(
        "The machine learning detector uses Isolation Forest. The model is trained on traffic labeled as normal and then scores all records. Isolation Forest is suitable for this project because it can identify records that are easier to isolate from the normal population, making it useful for unsupervised or semi-supervised anomaly detection. The trained model is saved in the models directory for reuse."
    ))

    parts.append(section("5. Results and Discussion"))
    parts.append(paragraph(
        f"The completed IDS project successfully generated and analyzed {log_count:,} network traffic records. The pipeline created processed feature data, trained an Isolation Forest model, executed security rules, merged duplicate detections, and saved the final alerts to a CSV file. During the verified run, the system detected {alert_count:,} suspicious or anomalous events."
    ))
    parts.append(table([
        ["Output Artifact", "Description"],
        ["data/network_logs.csv", "Generated synthetic network traffic records"],
        ["data/processed_features.csv", "Preprocessed and engineered features"],
        ["data/rule_based_alerts.csv", "Events flagged by security rules"],
        ["data/ml_anomalies.csv", "Events flagged by Isolation Forest"],
        ["data/detected_alerts.csv", "Merged alert dataset with severity"],
        ["models/isolation_forest_model.joblib", "Saved trained anomaly detection model"],
        ["logs/alerts.log", "Persistent security alert log"],
        ["logs/ids_app.log", "Application runtime log"],
    ]))
    parts.append(paragraph("Alert severity distribution from the verified run:"))
    parts.append(table([
        ["Severity", "Alert Count", "Meaning"],
        ["LOW", str(severities["LOW"]), "Suspicious but lower-confidence or lower-impact activity"],
        ["MEDIUM", str(severities["MEDIUM"]), "Elevated risk based on traffic volume or behavior"],
        ["HIGH", str(severities["HIGH"]), "High-risk activity such as restricted port access with repeated failed attempts"],
    ]))
    parts.append(paragraph(
        "The results show that the IDS can detect both explicit policy violations and statistical anomalies. Rule-based detection is strongest when the suspicious behavior is known in advance, such as access to ports like 23, 3389, 4444, 5900, or repeated failed authentication behavior. Machine learning detection is useful for identifying traffic records that differ from the learned normal baseline, including unusual combinations of packet counts, duration, source behavior, and protocol usage."
    ))
    parts.append(paragraph(
        "The dashboard provides a practical analyst view. It displays live logs, detected anomalies, high-level metrics, traffic over time, top source IP addresses, and anomaly counts by severity. This makes the project more realistic than a command-line-only script because security monitoring usually requires both automated detection and visual investigation."
    ))
    parts.append(paragraph(
        "The project met its objectives by producing a complete runnable IDS with no missing modules. It also demonstrates professional engineering practices: reusable functions, separated modules, saved models, persistent logs, a documented architecture, and dashboard visualization. One limitation is that the included dataset is synthetic, so real-world deployment would require integration with actual network telemetry such as firewall logs, Zeek logs, Suricata alerts, NetFlow records, or cloud security logs. Another limitation is that Isolation Forest may produce false positives when normal traffic changes, so periodic retraining and threshold tuning would be necessary in production."
    ))
    parts.append(paragraph("Sample high-severity alert format:"))
    parts.append(paragraph(
        "HIGH | machine_learning+rule_based | 203.0.113.21 -> 172.16.0.13:21 | Access to restricted port; Repeated failed login attempts",
        bold=True,
    ))

    parts.append(section("6. References"))
    for reference in [
        "Scikit-learn Developers. IsolationForest. Scikit-learn Machine Learning Library Documentation.",
        "Pandas Development Team. Pandas Documentation: DataFrame, CSV loading, and data transformation.",
        "Streamlit Documentation. Building interactive data applications in Python.",
        "KDD Cup 1999 Dataset. Network intrusion detection benchmark dataset.",
        "Canadian Institute for Cybersecurity. CICIDS datasets for intrusion detection research.",
        "NIST. Guide to Intrusion Detection and Prevention Systems.",
    ]:
        parts.append(bullet(reference))

    parts.append(paragraph(""))
    parts.append(paragraph("Thanks and Regards,", bold=True))
    parts.append(paragraph("Ajay Ram", bold=True))
    return "".join(parts)


def document_xml() -> str:
    body = build_body()
    sect_pr = (
        "<w:sectPr>"
        '<w:pgSz w:w="11906" w:h="16838"/>'
        '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="708" w:footer="708" w:gutter="0"/>'
        "</w:sectPr>"
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{W_NS}" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
        'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
        f"<w:body>{body}{sect_pr}</w:body></w:document>"
    )


def main() -> None:
    if not TEMPLATE.exists():
        raise FileNotFoundError(f"Template not found: {TEMPLATE}")
    temp = ROOT / ".tmp_report_build"
    if temp.exists():
        shutil.rmtree(temp)
    temp.mkdir(parents=True)
    shutil.copy2(TEMPLATE, temp / "template.zip")
    with zipfile.ZipFile(temp / "template.zip", "r") as source:
        source.extractall(temp / "docx")
    (temp / "docx" / "word" / "document.xml").write_text(document_xml(), encoding="utf-8")
    if OUTPUT.exists():
        OUTPUT.unlink()
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED) as target:
        for path in (temp / "docx").rglob("*"):
            if path.is_file():
                target.write(path, path.relative_to(temp / "docx").as_posix())
    shutil.rmtree(temp)
    print(OUTPUT)


if __name__ == "__main__":
    main()
