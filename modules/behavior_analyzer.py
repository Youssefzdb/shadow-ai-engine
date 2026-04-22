import re

ATTACK_SIGNATURES = {
    "SQL Injection": [r"union\s+select", r"or\s+1=1", r"'\s*or\s*'", r"drop\s+table"],
    "XSS": [r"<script>", r"onerror=", r"javascript:"],
    "Path Traversal": [r"\.\./", r"etc/passwd", r"etc/shadow"],
    "Command Injection": [r";\s*ls", r"\|\s*cat", r"&&\s*id"],
    "Scanner": [r"nmap", r"sqlmap", r"nikto", r"masscan"],
}

class BehaviorAnalyzer:
    def __init__(self, logfile):
        self.logfile = logfile

    def analyze(self):
        findings = []
        try:
            with open(self.logfile, "r", errors="ignore") as f:
                for i, line in enumerate(f, 1):
                    lower = line.lower()
                    for attack_type, patterns in ATTACK_SIGNATURES.items():
                        for pat in patterns:
                            if re.search(pat, lower):
                                findings.append({
                                    "line": i,
                                    "attack_type": attack_type,
                                    "pattern": pat,
                                    "raw": line.strip()[:120]
                                })
                                print(f"[!] {attack_type} detected at line {i}")
                                break
        except:
            pass
        return findings
