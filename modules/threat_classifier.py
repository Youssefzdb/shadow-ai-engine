#!/usr/bin/env python3
"""Threat Classifier - Rule-based threat classification"""

THREAT_RULES = [
    {"pattern": "z_score > 5", "label": "DDoS Attack", "severity": "CRITICAL"},
    {"pattern": "z_score > 3", "label": "Brute Force", "severity": "HIGH"},
    {"pattern": "z_score > 2.5", "label": "Port Scan", "severity": "MEDIUM"},
]

class ThreatClassifier:
    def classify(self, anomalies):
        classified = []
        for anomaly in anomalies:
            z = anomaly.get("z_score", 0)
            label = "Suspicious Activity"
            severity = "LOW"

            if z > 5:
                label, severity = "DDoS Attack", "CRITICAL"
            elif z > 3:
                label, severity = "Brute Force", "HIGH"
            elif z > 2.5:
                label, severity = "Port Scan / Recon", "MEDIUM"

            classified.append({
                **anomaly,
                "label": label,
                "severity": severity
            })
            print(f"[!] {severity}: {label} from {anomaly['ip']}")
        return classified
