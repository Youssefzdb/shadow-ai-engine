#!/usr/bin/env python3
"""Traffic Classifier - Rule-based ML-style traffic classification"""
import csv
import re

ATTACK_SIGNATURES = {
    "Port Scan": lambda r: int(r.get("dest_port", 0)) in range(1, 1025) and r.get("flags", "") == "S",
    "SQL Injection": lambda r: any(p in r.get("payload", "").lower() for p in ["union select", "' or '1'='1", "drop table"]),
    "XSS": lambda r: "<script>" in r.get("payload", "").lower(),
    "DDoS": lambda r: int(r.get("pkt_count", 0)) > 10000,
    "Brute Force": lambda r: r.get("status", "") in ["401", "403"] and int(r.get("count", 0)) > 50,
}

class TrafficClassifier:
    def __init__(self, filepath):
        self.filepath = filepath

    def classify(self):
        classifications = []
        try:
            with open(self.filepath, newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    for attack_type, rule in ATTACK_SIGNATURES.items():
                        try:
                            if rule(row):
                                classifications.append({
                                    "type": attack_type,
                                    "data": dict(row)
                                })
                                print(f"[!] Classified: {attack_type}")
                                break
                        except:
                            pass
        except:
            pass
        return classifications
