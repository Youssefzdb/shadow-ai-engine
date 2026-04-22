#!/usr/bin/env python3
"""Anomaly Detector - Statistical + ML-based detection"""

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    HAS_ML = True
except ImportError:
    HAS_ML = False

class AnomalyDetector:
    def __init__(self, features, threshold=0.8):
        self.features = features
        self.threshold = threshold

    def detect(self):
        if not self.features:
            return []

        anomalies = []

        if HAS_ML:
            import numpy as np
            X = np.array([[
                f["total_requests"],
                f["error_rate"],
                f["path_diversity"],
                f["unique_paths"]
            ] for f in self.features])

            clf = IsolationForest(contamination=0.1, random_state=42)
            preds = clf.fit_predict(X)
            scores = clf.decision_function(X)

            for i, (pred, score) in enumerate(zip(preds, scores)):
                if pred == -1:
                    f = dict(self.features[i])
                    f["anomaly_score"] = round(abs(score), 3)
                    anomalies.append(f)
                    print(f"[!] Anomaly: {f['ip']} (score={f['anomaly_score']})")
        else:
            # Fallback: statistical rules
            for f in self.features:
                score = 0
                if f["error_rate"] > 0.5: score += 0.4
                if f["total_requests"] > 1000: score += 0.3
                if f["path_diversity"] > 0.8: score += 0.3
                if score >= self.threshold:
                    f2 = dict(f)
                    f2["anomaly_score"] = round(score, 3)
                    anomalies.append(f2)
                    print(f"[!] Anomaly: {f2['ip']} (score={score})")

        return anomalies
