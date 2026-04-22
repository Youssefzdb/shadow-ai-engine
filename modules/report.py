#!/usr/bin/env python3
"""AI Engine Report Generator"""
from datetime import datetime
import json

class AIReport:
    def __init__(self, results):
        self.results = results

    def save(self, filename):
        threats = self.results.get("threats", [])
        critical = [t for t in threats if t.get("severity") == "CRITICAL"]
        high = [t for t in threats if t.get("severity") == "HIGH"]

        threats_html = ""
        for t in threats:
            color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#44ff88"}.get(t["severity"], "#fff")
            threats_html += f"<tr><td style='color:{color}'>{t['severity']}</td><td>{t['label']}</td><td>{t['ip']}</td><td>{t.get('count',0)}</td><td>{t.get('z_score',0)}</td></tr>"

        html = f"""<!DOCTYPE html>
<html>
<head><title>Shadow AI Engine Report</title>
<style>
body{{font-family:Arial;background:#070b14;color:#a0c4ff;padding:20px}}
h1{{color:#00d4ff}} h2{{color:#7b68ee}}
.card{{background:#0f1923;border-radius:8px;padding:15px;margin:10px 0;border-left:3px solid #00d4ff}}
.critical{{border-color:#ff4444}} .high{{border-color:#ff8800}}
table{{width:100%;border-collapse:collapse}}
td,th{{padding:8px;border:1px solid #1a2a3a}}
th{{background:#0a1628}}
</style></head>
<body>
<h1>Shadow AI Engine - Threat Analysis Report</h1>
<p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<div class="card"><h2>Summary</h2>
<p>Total Anomalies: {len(threats)} | Critical: {len(critical)} | High: {len(high)}</p></div>
<div class="card"><h2>Detected Threats</h2>
<table><tr><th>Severity</th><th>Type</th><th>IP</th><th>Requests</th><th>Z-Score</th></tr>
{threats_html}</table></div>
</body></html>"""
        with open(filename, "w") as f:
            f.write(html)
        print(f"[+] AI report saved: {filename}")
