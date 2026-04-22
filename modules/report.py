#!/usr/bin/env python3
from datetime import datetime

class Report:
    def __init__(self, source, features, anomalies, threats):
        self.source = source
        self.features = features
        self.anomalies = anomalies
        self.threats = threats

    def save(self, filename):
        threat_html = "".join(
            f"<tr><td>{t['ip']}</td><td>{t['threat_type']}</td><td>{t['anomaly_score']}</td><td>{t['total_requests']}</td><td>{t['error_rate']}</td></tr>"
            for t in self.threats
        )
        html = f"""<!DOCTYPE html><html><head><title>Shadow AI Engine</title>
<style>body{{font-family:monospace;background:#000520;color:#00d4ff;padding:20px}}
h1{{color:#00ffff}}table{{width:100%;border-collapse:collapse;margin:10px 0}}
td,th{{padding:7px;border:1px solid #003355}}th{{background:#001133}}
.high{{color:#ff4444}}.medium{{color:#ffaa00}}</style></head>
<body><h1>Shadow AI Engine - Threat Report</h1>
<p>Source: <b>{self.source}</b> | Features: {len(self.features)} | Anomalies: {len(self.anomalies)} | {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<h2>Classified Threats</h2>
<table><tr><th>IP</th><th>Threat Type</th><th>Score</th><th>Requests</th><th>Error Rate</th></tr>
{threat_html if threat_html else '<tr><td colspan=5>No threats detected</td></tr>'}
</table></body></html>"""
        with open(filename, "w") as f:
            f.write(html)
        print(f"[+] Saved: {filename}")
