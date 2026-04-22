#!/usr/bin/env python3
"""Feature Extractor - Convert log entries to ML feature vectors"""
import re
from collections import defaultdict

class FeatureExtractor:
    def __init__(self, filepath):
        self.filepath = filepath

    def extract(self):
        features = []
        ip_counts = defaultdict(int)
        ip_errors = defaultdict(int)
        ip_paths = defaultdict(set)

        try:
            with open(self.filepath, "r", errors="ignore") as f:
                for line in f:
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+).*?(\d{3})', line)
                    if m:
                        ip = m.group(1)
                        status = int(m.group(2))
                        ip_counts[ip] += 1
                        if status >= 400:
                            ip_errors[ip] += 1
                        path_m = re.search(r'"[A-Z]+ (/[^\s"]*)', line)
                        if path_m:
                            ip_paths[ip].add(path_m.group(1))
        except Exception as e:
            print(f"[-] Feature extraction error: {e}")
            return []

        for ip in ip_counts:
            total = ip_counts[ip]
            errors = ip_errors[ip]
            paths = len(ip_paths[ip])
            error_rate = errors / total if total > 0 else 0
            features.append({
                "ip": ip,
                "total_requests": total,
                "error_count": errors,
                "unique_paths": paths,
                "error_rate": round(error_rate, 3),
                "path_diversity": round(paths / total, 3) if total > 0 else 0
            })
        return features
