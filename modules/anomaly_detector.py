#!/usr/bin/env python3
"""Anomaly Detector - Statistical anomaly detection on network logs"""
import csv
import statistics
from collections import defaultdict

class AnomalyDetector:
    def __init__(self, filepath, threshold=2.5):
        self.filepath = filepath
        self.threshold = threshold  # Z-score threshold

    def _load(self):
        rows = []
        try:
            with open(self.filepath, newline="") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
        except:
            pass
        return rows

    def detect(self):
        rows = self._load()
        if not rows:
            return []

        anomalies = []
        ip_counts = defaultdict(int)
        byte_counts = defaultdict(list)

        for row in rows:
            ip = row.get("src_ip", row.get("ip", "unknown"))
            ip_counts[ip] += 1
            try:
                bytes_val = int(row.get("bytes", row.get("size", 0)))
                byte_counts[ip].append(bytes_val)
            except:
                pass

        # Z-score detection on request counts
        counts = list(ip_counts.values())
        if len(counts) > 2:
            mean = statistics.mean(counts)
            stdev = statistics.stdev(counts) or 1
            for ip, count in ip_counts.items():
                z_score = (count - mean) / stdev
                if abs(z_score) > self.threshold:
                    anomalies.append({
                        "ip": ip, "count": count,
                        "z_score": round(z_score, 2),
                        "type": "Traffic Spike" if z_score > 0 else "Unusual Drop"
                    })
                    print(f"[!] Anomaly: {ip} | z={z_score:.2f} | count={count}")

        print(f"[+] Detected {len(anomalies)} anomalies")
        return anomalies
