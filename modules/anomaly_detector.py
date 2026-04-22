#!/usr/bin/env python3
"""Anomaly Detector using statistical analysis"""
import statistics
from collections import Counter

class AnomalyDetector:
    def __init__(self, profile):
        self.profile = profile
        self.threshold = 2.5  # standard deviations

    def train(self):
        """Build baseline from profile data"""
        self.baseline = {
            "mean_requests": statistics.mean(self.profile.get("request_counts", [1])),
            "stdev_requests": statistics.stdev(self.profile.get("request_counts", [1, 1])) if len(self.profile.get("request_counts", [])) > 1 else 1,
        }
        print(f"[+] Baseline trained: mean={self.baseline['mean_requests']:.2f}")

    def detect(self):
        anomalies = []
        ip_counts = self.profile.get("ip_counts", {})
        
        if not ip_counts:
            return anomalies

        counts = list(ip_counts.values())
        if len(counts) < 2:
            return anomalies

        mean = statistics.mean(counts)
        stdev = statistics.stdev(counts)

        for ip, count in ip_counts.items():
            z_score = (count - mean) / stdev if stdev > 0 else 0
            if z_score > self.threshold:
                anomalies.append({
                    "ip": ip,
                    "count": count,
                    "z_score": round(z_score, 2),
                    "type": "Statistical Anomaly"
                })
                print(f"[!] Anomaly detected: {ip} z-score={z_score:.2f}")

        return anomalies
