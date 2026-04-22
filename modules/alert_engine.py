class AlertEngine:
    def __init__(self, anomalies, behaviors):
        self.anomalies = anomalies
        self.behaviors = behaviors

    def evaluate(self):
        alerts = []
        for a in self.anomalies:
            if a["verdict"] == "HIGH":
                alerts.append({
                    "type": "CRITICAL",
                    "message": f"High anomaly score from {a['ip']} ({a['request_count']} requests)",
                    "ip": a["ip"]
                })

        attack_types = {}
        for b in self.behaviors:
            t = b["attack_type"]
            attack_types[t] = attack_types.get(t, 0) + 1

        for attack_type, count in attack_types.items():
            alerts.append({
                "type": "WARNING",
                "message": f"{attack_type} detected {count} times",
                "count": count
            })
        return alerts
