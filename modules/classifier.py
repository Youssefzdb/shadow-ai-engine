#!/usr/bin/env python3
"""Threat Classifier - Categorize anomalies into threat types"""

RULES = [
    {"label": "Brute Force",     "cond": lambda f: f["error_rate"] > 0.6 and f["total_requests"] > 50},
    {"label": "Web Scanner",     "cond": lambda f: f["path_diversity"] > 0.7},
    {"label": "DDoS",            "cond": lambda f: f["total_requests"] > 5000},
    {"label": "Data Exfiltration","cond": lambda f: f["unique_paths"] > 100 and f["error_rate"] < 0.1},
]

class ThreatClassifier:
    def __init__(self, anomalies):
        self.anomalies = anomalies

    def classify(self):
        classified = []
        for a in self.anomalies:
            labels = []
            for rule in RULES:
                try:
                    if rule["cond"](a):
                        labels.append(rule["label"])
                except:
                    pass
            a["threat_type"] = ", ".join(labels) if labels else "Unknown Anomaly"
            classified.append(a)
            print(f"[+] {a['ip']} classified as: {a['threat_type']}")
        return classified
