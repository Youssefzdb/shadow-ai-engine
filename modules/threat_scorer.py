#!/usr/bin/env python3
"""Threat Scorer - Compute overall threat score"""

class ThreatScorer:
    def __init__(self, results):
        self.results = results

    def score(self):
        score = 0
        anomalies = len(self.results.get("anomalies", []))
        classifications = len(self.results.get("classifications", []))

        score += min(anomalies * 10, 50)
        score += min(classifications * 15, 50)

        level = "LOW"
        if score >= 70:
            level = "CRITICAL"
        elif score >= 40:
            level = "HIGH"
        elif score >= 20:
            level = "MEDIUM"

        print(f"[+] Threat Score: {score}/100 ({level})")
        return {"score": score, "level": level}
