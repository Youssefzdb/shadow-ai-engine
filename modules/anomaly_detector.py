import re
from collections import Counter
from statistics import mean, stdev

class AnomalyDetector:
    def __init__(self, logfile, threshold=0.85):
        self.logfile = logfile
        self.threshold = threshold

    def load_entries(self):
        entries = []
        try:
            with open(self.logfile, "r", errors="ignore") as f:
                for line in f:
                    ip_match = re.search(r"\b(\d{1,3}\.){3}\d{1,3}\b", line)
                    if ip_match:
                        entries.append({"ip": ip_match.group(), "raw": line.strip()})
        except:
            pass
        return entries

    def detect(self):
        entries = self.load_entries()
        if not entries:
            return []

        ip_counts = Counter(e["ip"] for e in entries)
        values = list(ip_counts.values())
        if len(values) < 2:
            return []

        avg = mean(values)
        sd = stdev(values) if len(values) > 1 else 1

        anomalies = []
        for ip, count in ip_counts.items():
            score = (count - avg) / (sd + 1)
            normalized = min(score / 10, 1.0)
            if normalized >= self.threshold:
                anomalies.append({
                    "ip": ip,
                    "request_count": count,
                    "anomaly_score": round(normalized, 3),
                    "verdict": "HIGH" if normalized > 0.9 else "MEDIUM"
                })
                print(f"[!] Anomaly [{anomalies[-1]['verdict']}]: {ip} score={normalized:.3f}")
        return anomalies
