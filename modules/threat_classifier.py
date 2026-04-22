#!/usr/bin/env python3
"""Threat Classifier - Classify anomalies into threat categories"""

THREAT_CATEGORIES = {
    "bytes_sent": "Data Exfiltration",
    "login_attempts": "Brute Force Attack",
    "cpu_usage": "Cryptomining / Resource Abuse",
    "connections": "Port Scanning / Lateral Movement",
    "file_access": "Unauthorized File Access",
}

MITRE_MAPPING = {
    "Data Exfiltration": "T1041 - Exfiltration Over C2 Channel",
    "Brute Force Attack": "T1110 - Brute Force",
    "Cryptomining / Resource Abuse": "T1496 - Resource Hijacking",
    "Port Scanning / Lateral Movement": "T1046 - Network Service Scanning",
    "Unauthorized File Access": "T1083 - File and Directory Discovery",
}

class ThreatClassifier:
    def __init__(self, anomalies):
        self.anomalies = anomalies

    def classify(self):
        threats = []
        for anomaly in self.anomalies:
            col = anomaly.get("column", "")
            category = THREAT_CATEGORIES.get(col, "Unknown Threat")
            mitre = MITRE_MAPPING.get(category, "Unknown")
            threats.append({
                "category": category,
                "mitre_technique": mitre,
                "severity": anomaly.get("severity", "MEDIUM"),
                "detail": anomaly
            })
            print(f"[+] Classified: {category} ({mitre})")
        return threats
