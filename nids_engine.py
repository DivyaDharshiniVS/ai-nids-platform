"""
nids_engine.py - Machine Learning Engine for Network Intrusion Detection System
AI-Based Network Intrusion Detection System
Capstone Project

Implements:
1. Preprocessing and feature engineering for network flow records.
2. Synthetic benchmark dataset generation modeled on NSL-KDD distributions.
3. Genuine Scikit-Learn RandomForestClassifier trained and validated with held-out test data.
4. Dynamic prediction, confidence calculation, threat classification, and alert synthesis.
5. Zero hardcoded evaluation metrics: all metrics (Accuracy, Precision, Recall, F1)
   are calculated dynamically from actual model predictions.
"""

import os
import random
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
from sklearn.model_selection import train_test_split

# Core feature schema expected for network flow analysis
FEATURE_COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "count",
    "srv_count",
    "serror_rate",
    "same_srv_rate",
    "dst_host_count",
    "dst_host_srv_count"
]

NUMERIC_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "count",
    "srv_count", "serror_rate", "same_srv_rate",
    "dst_host_count", "dst_host_srv_count"
]

CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]

PROTOCOL_OPTIONS = ["tcp", "udp", "icmp"]
SERVICE_OPTIONS = ["http", "dns", "smtp", "ftp", "ssh", "telnet", "private", "other"]
FLAG_OPTIONS = ["SF", "S0", "REJ", "RSTO", "RSTR"]

# Global cache for trained model and held-out validation results
_CACHED_MODEL = None
_CACHED_METRICS = None
_CACHED_FEATURE_NAMES = None


def generate_synthetic_nids_data(n_samples: int = 1500, random_seed: int = 42) -> pd.DataFrame:
    """
    Generates a realistic synthetic network traffic dataset modeled on benchmark NIDS distributions.
    Simulates:
    - Normal (65%): Standard HTTP, DNS, SSH, SMTP flows with SF flags, normal byte ratios.
    - DoS Attack (18%): High connection counts, high serror_rate, S0 flags, SYN flood patterns.
    - PortScan / Probe (12%): Probing multiple services, high dst_host_count, REJ / S0 flags.
    - Unauthorized Access / R2L (5%): Unusual payload sizes, repeated failed service authentications.
    """
    np.random.seed(random_seed)
    random.seed(random_seed)

    records = []
    
    # 1. Normal Traffic (~65%)
    n_normal = int(n_samples * 0.65)
    for i in range(n_normal):
        proto = np.random.choice(["tcp", "udp"], p=[0.75, 0.25])
        srv = np.random.choice(["http", "dns", "ssh", "smtp", "ftp"], p=[0.55, 0.20, 0.12, 0.08, 0.05])
        if proto == "udp":
            srv = "dns"
        duration = float(np.round(np.random.exponential(scale=1.5), 2))
        src_bytes = int(np.random.randint(40, 3500))
        dst_bytes = int(np.random.randint(100, 25000))
        count = int(np.random.randint(1, 15))
        srv_count = int(np.random.randint(1, 12))
        serror_rate = float(np.round(np.random.uniform(0.0, 0.05), 3))
        same_srv_rate = float(np.round(np.random.uniform(0.85, 1.0), 3))
        dst_host_count = int(np.random.randint(5, 80))
        dst_host_srv_count = int(np.random.randint(10, 100))
        flag = "SF"
        src_ip = f"192.168.1.{np.random.randint(2, 200)}"
        dst_ip = f"10.0.0.{np.random.randint(1, 20)}"
        records.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "duration": duration,
            "protocol_type": proto,
            "service": srv,
            "flag": flag,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "count": count,
            "srv_count": srv_count,
            "serror_rate": serror_rate,
            "same_srv_rate": same_srv_rate,
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "label": "Normal",
            "threat_category": "Normal",
            "severity": "Low"
        })

    # 2. DoS Attacks (~18%): High count, high serror_rate, S0 flag, zero/low dst_bytes
    n_dos = int(n_samples * 0.18)
    for i in range(n_dos):
        proto = "tcp"
        srv = np.random.choice(["http", "private", "other"], p=[0.70, 0.20, 0.10])
        duration = 0.0
        src_bytes = int(np.random.randint(0, 120))
        dst_bytes = 0
        count = int(np.random.randint(150, 512))
        srv_count = int(np.random.randint(100, 450))
        serror_rate = float(np.round(np.random.uniform(0.88, 1.0), 3))
        same_srv_rate = float(np.round(np.random.uniform(0.90, 1.0), 3))
        dst_host_count = 255
        dst_host_srv_count = int(np.random.randint(1, 25))
        flag = "S0"
        src_ip = f"45.33.{np.random.randint(1, 100)}.{np.random.randint(2, 250)}"
        dst_ip = "10.0.0.5" # Web server targeted
        records.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "duration": duration,
            "protocol_type": proto,
            "service": srv,
            "flag": flag,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "count": count,
            "srv_count": srv_count,
            "serror_rate": serror_rate,
            "same_srv_rate": same_srv_rate,
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "label": "Malicious",
            "threat_category": "DoS Attack",
            "severity": "Critical"
        })

    # 3. PortScan / Probe (~12%): Probing multiple services, REJ / S0 flags
    n_probe = int(n_samples * 0.12)
    for i in range(n_probe):
        proto = np.random.choice(["tcp", "icmp"], p=[0.85, 0.15])
        srv = np.random.choice(["private", "other", "telnet", "http", "ssh"])
        duration = float(np.round(np.random.uniform(0.0, 0.1), 2))
        src_bytes = int(np.random.randint(0, 64))
        dst_bytes = 0
        count = int(np.random.randint(25, 120))
        srv_count = int(np.random.randint(1, 8))
        serror_rate = float(np.round(np.random.uniform(0.20, 0.85), 3))
        same_srv_rate = float(np.round(np.random.uniform(0.05, 0.25), 3))
        dst_host_count = 255
        dst_host_srv_count = int(np.random.randint(1, 15))
        flag = np.random.choice(["REJ", "RSTO", "S0"])
        src_ip = f"198.51.100.{np.random.randint(10, 200)}"
        dst_ip = f"10.0.0.{np.random.randint(1, 20)}"
        records.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "duration": duration,
            "protocol_type": proto,
            "service": srv,
            "flag": flag,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "count": count,
            "srv_count": srv_count,
            "serror_rate": serror_rate,
            "same_srv_rate": same_srv_rate,
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "label": "Malicious",
            "threat_category": "PortScan / Probe",
            "severity": "High"
        })

    # 4. Unauthorized Access / R2L (~5%): Abnormal byte payloads on sensitive services
    n_r2l = n_samples - len(records)
    for i in range(max(1, n_r2l)):
        proto = "tcp"
        srv = np.random.choice(["ftp", "ssh", "telnet"], p=[0.4, 0.4, 0.2])
        duration = float(np.round(np.random.uniform(2.0, 25.0), 2))
        src_bytes = int(np.random.randint(2500, 15000))
        dst_bytes = int(np.random.randint(100, 1500))
        count = int(np.random.randint(3, 20))
        srv_count = int(np.random.randint(1, 5))
        serror_rate = float(np.round(np.random.uniform(0.0, 0.15), 3))
        same_srv_rate = float(np.round(np.random.uniform(0.60, 0.90), 3))
        dst_host_count = int(np.random.randint(20, 120))
        dst_host_srv_count = int(np.random.randint(1, 10))
        flag = np.random.choice(["SF", "RSTO"])
        src_ip = f"203.0.113.{np.random.randint(1, 150)}"
        dst_ip = "10.0.0.8"
        records.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "duration": duration,
            "protocol_type": proto,
            "service": srv,
            "flag": flag,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "count": count,
            "srv_count": srv_count,
            "serror_rate": serror_rate,
            "same_srv_rate": same_srv_rate,
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "label": "Malicious",
            "threat_category": "Unauthorized Access",
            "severity": "Critical"
        })

    df = pd.DataFrame(records)
    df = df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)
    return df


def preprocess_features(df: pd.DataFrame, trained_feature_names: List[str] = None) -> Tuple[np.ndarray, List[str]]:
    """
    Transforms raw network flow records into a numerical feature matrix using One-Hot Encoding.
    If trained_feature_names is provided, aligns columns exactly with the model schema.
    """
    df_clean = df.copy()

    # Ensure all required numeric columns exist with default 0
    for col in NUMERIC_FEATURES:
        if col in df_clean.columns:
            df_clean[col] = pd.to_numeric(df_clean[col], errors="coerce").fillna(0.0)
        else:
            df_clean[col] = 0.0

    # Ensure categorical columns exist with lowercase defaults
    for col in CATEGORICAL_FEATURES:
        if col in df_clean.columns:
            df_clean[col] = df_clean[col].astype(str).str.lower().str.strip()
        else:
            df_clean[col] = "other"

    # One-hot encode categoricals
    df_encoded = pd.get_dummies(df_clean[FEATURE_COLUMNS], columns=CATEGORICAL_FEATURES, drop_first=False)

    if trained_feature_names is not None:
        # Reindex to match trained features exactly (adding missing as 0, dropping unknown)
        df_encoded = df_encoded.reindex(columns=trained_feature_names, fill_value=0)
        feature_names = trained_feature_names
    else:
        feature_names = list(df_encoded.columns)

    return df_encoded.values.astype(np.float32), feature_names


def train_nids_model() -> Tuple[RandomForestClassifier, Dict[str, Any], List[str]]:
    """
    Trains a genuine Scikit-Learn RandomForestClassifier on benchmark network flows.
    Evaluates model on an independent held-out test split (25%) and computes real metrics:
    - Accuracy, Precision, Recall, F1-Score, Confusion Matrix, and Feature Importances.
    """
    global _CACHED_MODEL, _CACHED_METRICS, _CACHED_FEATURE_NAMES

    if _CACHED_MODEL is not None:
        return _CACHED_MODEL, _CACHED_METRICS, _CACHED_FEATURE_NAMES

    df_all = generate_synthetic_nids_data(n_samples=2000, random_seed=42)

    X_raw, feature_names = preprocess_features(df_all)
    y_raw = df_all["label"].values # Binary: "Normal" or "Malicious"

    # Split into train (75%) and held-out test (25%)
    X_train, X_test, y_train, y_test = train_test_split(
        X_raw, y_raw, test_size=0.25, random_state=42, stratify=y_raw
    )

    # Train genuine Random Forest Classifier
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=14,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)

    # Compute REAL evaluation metrics on held-out test set
    y_pred = rf.predict(X_test)
    y_proba = rf.predict_proba(X_test)

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, pos_label="Malicious", average="binary"))
    rec = float(recall_score(y_test, y_pred, pos_label="Malicious", average="binary"))
    f1 = float(f1_score(y_test, y_pred, pos_label="Malicious", average="binary"))
    cm = confusion_matrix(y_test, y_pred, labels=["Normal", "Malicious"]).tolist()

    # Feature importances
    importances = rf.feature_importances_
    top_feature_indices = np.argsort(importances)[::-1][:10]
    top_features = [
        {"feature": feature_names[idx], "importance": round(float(importances[idx]), 4)}
        for idx in top_feature_indices
    ]

    metrics = {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "test_sample_count": len(y_test),
        "train_sample_count": len(y_train),
        "confusion_matrix": cm,
        "top_features": top_features,
        "classes": list(rf.classes_)
    }

    _CACHED_MODEL = rf
    _CACHED_METRICS = metrics
    _CACHED_FEATURE_NAMES = feature_names

    return rf, metrics, feature_names


def analyze_uploaded_traffic(df_input: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Performs full intrusion detection analysis on an uploaded or sample DataFrame:
    1. Validates and preprocesses features to match the trained model.
    2. Executes model inference to generate predictions and confidence scores.
    3. Categorizes specific threat vectors (DoS, PortScan, Unauthorized Access).
    4. Synthesizes actionable, text-based security alerts.
    """
    model, metrics, feature_names = train_nids_model()

    # Preprocess
    X_matrix, _ = preprocess_features(df_input, trained_feature_names=feature_names)

    # Real predictions & confidence scores
    predictions = model.predict(X_matrix)
    probabilities = model.predict_proba(X_matrix)
    
    # Identify index of "Malicious" class in model.classes_
    classes_list = list(model.classes_)
    malicious_idx = classes_list.index("Malicious") if "Malicious" in classes_list else 1

    results_df = df_input.copy()
    results_df["predicted_label"] = predictions
    results_df["anomaly_confidence"] = np.round(probabilities[:, malicious_idx] * 100, 1)

    # Assign dynamic threat category & severity based on pattern analysis
    threat_cats = []
    severities = []
    alerts = []

    for idx, row in results_df.iterrows():
        is_malicious = (row["predicted_label"] == "Malicious")
        serror = float(row.get("serror_rate", 0))
        count_val = float(row.get("count", 0))
        flag_val = str(row.get("flag", "")).upper()
        srv_val = str(row.get("service", "")).lower()
        src_ip = str(row.get("src_ip", f"192.168.1.{random.randint(10, 240)}"))
        dst_ip = str(row.get("dst_ip", "10.0.0.1"))
        proto = str(row.get("protocol_type", "tcp")).upper()

        if is_malicious:
            if count_val > 100 or serror > 0.5 or flag_val == "S0":
                cat = "DoS Attack (SYN Flood)"
                sev = "Critical"
                alert_text = (
                    f"[CRITICAL] {proto} SYN Flood detected from {src_ip} -> {dst_ip}. "
                    f"Abnormal connection count ({int(count_val)}) with S0 flag. "
                    f"Mitigation: Apply iptables SYN rate-limit & drop traffic from {src_ip}."
                )
            elif str(row.get("dst_host_count", 0)) == "255" or flag_val in ["REJ", "RSTO"]:
                cat = "PortScan / Network Probe"
                sev = "High"
                alert_text = (
                    f"[HIGH] Stealth Port Scan / Service Sweep detected from {src_ip}. "
                    f"Targeting host {dst_ip} across service '{srv_val}'. "
                    f"Mitigation: Block scanner source IP at border gateway."
                )
            else:
                cat = "Unauthorized Access / R2L"
                sev = "High"
                alert_text = (
                    f"[HIGH] Unauthorized Access attempt detected on service '{srv_val}' from {src_ip}. "
                    f"Payload anomaly observed. Mitigation: Terminate active TCP session and inspect auth logs."
                )
            threat_cats.append(cat)
            severities.append(sev)
            alerts.append({
                "alert_id": f"ALT-{random.randint(1000, 9999)}",
                "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "protocol": proto,
                "threat_type": cat,
                "severity": sev,
                "alert_message": alert_text
            })
        else:
            threat_cats.append("Normal Traffic")
            severities.append("None")

    results_df["threat_category"] = threat_cats
    results_df["severity"] = severities

    total_packets = len(results_df)
    malicious_count = int((results_df["predicted_label"] == "Malicious").sum())
    normal_count = total_packets - malicious_count
    anomaly_rate = round((malicious_count / total_packets) * 100, 1) if total_packets > 0 else 0.0

    summary = {
        "total_packets": total_packets,
        "normal_count": normal_count,
        "malicious_count": malicious_count,
        "anomaly_rate": anomaly_rate,
        "critical_alerts": sum(1 for s in severities if s == "Critical"),
        "high_alerts": sum(1 for s in severities if s == "High"),
        "alerts_list": alerts,
        "model_metrics": metrics
    }

    return results_df, summary


def create_benchmark_csv_if_missing(file_path: str = "sample_network_traffic.csv"):
    """Creates a local sample dataset file if not present so users can test immediately with 1 click."""
    if not os.path.exists(file_path):
        df_sample = generate_synthetic_nids_data(n_samples=120, random_seed=101)
        # Drop ground-truth labels from the raw input file so it acts like an unlabelled capture
        cols_to_save = [
            "src_ip", "dst_ip", "duration", "protocol_type", "service", "flag",
            "src_bytes", "dst_bytes", "count", "srv_count", "serror_rate",
            "same_srv_rate", "dst_host_count", "dst_host_srv_count"
        ]
        df_sample[cols_to_save].to_csv(file_path, index=False)
        print(f"Generated benchmark dataset at {file_path}")

# Initialize benchmark CSV on import
create_benchmark_csv_if_missing()
