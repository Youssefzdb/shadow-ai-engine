#!/usr/bin/env python3
"""Behavior Analyzer - Detect unusual user/system behavior patterns"""
import csv
from collections import Counter

SUSPICIOUS_BEHAVIORS = {
    "after_hours_login": "Login outside working hours (00:00-06:00)",
    "multiple_failed_logins": "Multiple failed login attempts",
    "large_data_transfer": "Unusually large data transfer",
    "new_admin_account": "New privileged account created",
    "lateral_movement": "Connection to multiple internal hosts",
}

class BehaviorAnalyzer:
    def __init__(self, filepath):
        self.filepath = filepath

    def analyze(self):
        behaviors = []
        print("[*] Analyzing behavioral patterns...")
        # Demo behavioral analysis
        demo_events = [
            {"user": "admin", "action": "login", "time": "02:30", "ip": "192.168.1.50"},
            {"user": "user1", "action": "failed_login", "count": 15, "ip": "10.0.0.5"},
            {"user": "svc_account", "action": "data_export", "size_mb": 2500},
        ]
        for event in demo_events:
            if event.get("time", "12:00")[:2] in ["00","01","02","03","04","05"]:
                behaviors.append({"type": "After Hours Activity", "detail": str(event), "severity": "MEDIUM"})
                print(f"[!] After-hours activity: {event.get('user')}")
            if event.get("count", 0) > 10:
                behaviors.append({"type": "Brute Force", "detail": str(event), "severity": "HIGH"})
                print(f"[!] Brute force: {event.get('user')}")
            if event.get("size_mb", 0) > 1000:
                behaviors.append({"type": "Data Exfiltration Risk", "detail": str(event), "severity": "HIGH"})
                print(f"[!] Large data export: {event.get('user')}")

        return behaviors
