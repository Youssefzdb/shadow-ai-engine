#!/usr/bin/env python3
"""Network Profiler - Build traffic profile from logs"""
import re
from collections import Counter, defaultdict

class NetworkProfiler:
    def __init__(self, logfile):
        self.logfile = logfile

    def build_profile(self):
        ip_counts = Counter()
        status_counts = Counter()
        path_counts = Counter()
        hourly = defaultdict(int)

        ip_pattern = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        status_pattern = re.compile(r'" (\d{3}) ')
        path_pattern = re.compile(r'"[A-Z]+ ([^ ]+) HTTP')

        try:
            with open(self.logfile, "r", errors="ignore") as f:
                for line in f:
                    ip_m = ip_pattern.match(line)
                    if ip_m:
                        ip_counts[ip_m.group(1)] += 1
                    status_m = status_pattern.search(line)
                    if status_m:
                        status_counts[status_m.group(1)] += 1
                    path_m = path_pattern.search(line)
                    if path_m:
                        path_counts[path_m.group(1)] += 1
        except FileNotFoundError:
            print(f"[-] File not found: {self.logfile}")

        print(f"[+] Profiled {sum(ip_counts.values())} requests from {len(ip_counts)} unique IPs")
        return {
            "ip_counts": dict(ip_counts.most_common(100)),
            "status_counts": dict(status_counts),
            "top_paths": dict(path_counts.most_common(20)),
            "request_counts": list(ip_counts.values()),
        }
