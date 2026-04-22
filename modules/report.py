#!/usr/bin/env python3
"""AI Threat Report Generator"""
from datetime import datetime

class AIReport:
    def __init__(self, source, results):
        self.source = source
        self.results = results

    def save(self, filename):
        anomalies = self.results.get("anomalies", [])
        behaviors = self.results.get("behaviors", [])
        threats = self.results.get("threats", [])

        def rows(items, keys):
            return "".join(
                "<tr>" + "".join(f"<td>{item.get(k,'')}</td>" for k in keys) + "</tr>"
                for item in items
            )

        html = f"""<!DOCTYPE html>
<html><head><title>Shadow AI Engine Report</title>
<style>
body{{font-family:Arial;background:#0a0a0a;color:#e0e0e0;padding:20px}}
h1{{color:#7c3aed}} h2{{color:#a78bfa}}
.card{{background:#1e1e2e;border-radius:8px;padding:15px;margin:10px 0;border-left:4px solid #7c3aed}}
table{{width:100%;border-collapse:collapse}} td,th{{padding:8px;border:1px solid #333}}
th{{background:#2d2d44}} .HIGH{{color:#ef4444}} .MEDIUM{{color:#f59e0b}} .LOW{{color:#22c55e}}
</style></head>
<body>
<h1>Shadow AI Engine — Threat Report</h1>
<p>Source: <b>{self.source}</b> | {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<div class="card">
  <h2>Anomalies Detected ({len(anomalies)})</h2>
  <table><tr><th>Column</th><th>Value</th><th>Z-Score</th><th>Severity</th></tr>
  {rows(anomalies, ['column','value','zscore','severity'])}</table>
</div>
<div class="card">
  <h2>Behavioral Alerts ({len(behaviors)})</h2>
  <table><tr><th>Type</th><th>Detail</th><th>Severity</th></tr>
  {rows(behaviors, ['type','detail','severity'])}</table>
</div>
<div class="card">
  <h2>Threat Classifications ({len(threats)})</h2>
  <table><tr><th>Category</th><th>MITRE ATT&CK</th><th>Severity</th></tr>
  {rows(threats, ['category','mitre_technique','severity'])}</table>
</div>
</body></html>"""
        with open(filename, "w") as f:
            f.write(html)

cat > /tmp/ai_req.txt << 'EOF'
colorama>=0.4.6
