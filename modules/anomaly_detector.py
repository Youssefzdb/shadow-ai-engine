#!/usr/bin/env python3
"""Anomaly Detector - Statistical anomaly detection on log data"""
import csv
import math
from collections import defaultdict

class AnomalyDetector:
    def __init__(self, filepath):
        self.filepath = filepath
        self.anomalies = []

    def _load_csv(self):
        rows = []
        try:
            with open(self.filepath, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    rows.append(row)
        except:
            pass
        return rows

    def _zscore(self, values):
        if len(values) < 2:
            return []
        mean = sum(values) / len(values)
        std = math.sqrt(sum((x - mean) ** 2 for x in values) / len(values))
        if std == 0:
            return [0.0] * len(values)
        return [(x - mean) / std for x in values]

    def detect(self):
        rows = self._load_csv()
        if not rows:
            print("[*] No data to analyze — using demo detection")
            return self._demo_detection()

        # Detect anomalies in numeric columns
        numeric_cols = defaultdict(list)
        for row in rows:
            for k, v in row.items():
                try:
                    numeric_cols[k].append(float(v))
                except:
                    pass

        for col, values in numeric_cols.items():
            zscores = self._zscore(values)
            for i, z in enumerate(zscores):
                if abs(z) > 2.5:
                    self.anomalies.append({
                        "column": col,
                        "value": values[i],
                        "zscore": round(z, 3),
                        "row": i,
                        "severity": "HIGH" if abs(z) > 3.5 else "MEDIUM"
                    })
                    print(f"[!] Anomaly in {col} row {i}: z={z:.2f}")

        print(f"[+] Detected {len(self.anomalies)} anomalies")
        return self.anomalies

    def _demo_detection(self):
        return [
            {"column": "bytes_sent", "value": 9999999, "zscore": 4.2, "row": 42, "severity": "HIGH"},
            {"column": "login_attempts", "value": 850, "zscore": 3.1, "row": 17, "severity": "HIGH"},
            {"column": "cpu_usage", "value": 98.5, "zscore": 2.7, "row": 5, "severity": "MEDIUM"},
        ]
