#!/usr/bin/env python3
"""
shadow-ai-engine - AI-Powered Threat Detection & Anomaly Analysis Engine
Uses ML to detect anomalies in network traffic and log data
"""
import argparse
from modules.anomaly_detector import AnomalyDetector
from modules.behavior_analyzer import BehaviorAnalyzer
from modules.alert_engine import AlertEngine
from modules.report import AIReport

def main():
    parser = argparse.ArgumentParser(description="ShadowAI Threat Detection Engine")
    parser.add_argument("--logs", required=True, help="Path to log file or directory")
    parser.add_argument("--threshold", type=float, default=0.85, help="Anomaly threshold (0-1)")
    parser.add_argument("--output", default="ai_threat_report.html")
    args = parser.parse_args()

    print(f"[*] ShadowAI Engine starting...")
    print(f"[*] Analyzing: {args.logs} | Threshold: {args.threshold}")

    detector = AnomalyDetector(args.logs, args.threshold)
    anomalies = detector.detect()

    behavior = BehaviorAnalyzer(args.logs)
    behaviors = behavior.analyze()

    alerts = AlertEngine(anomalies, behaviors)
    triggered = alerts.evaluate()

    report = AIReport(anomalies, behaviors, triggered)
    report.save(args.output)
    print(f"[+] Detected {len(anomalies)} anomalies, {len(triggered)} alerts. Report: {args.output}")

if __name__ == "__main__":
    main()
