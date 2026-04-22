#!/usr/bin/env python3
"""
shadow-ai-engine - AI-Powered Threat Detection & Anomaly Analysis Engine
Uses ML to detect anomalies in network traffic, logs, and system behavior
"""
import argparse
from modules.anomaly_detector import AnomalyDetector
from modules.behavior_analyzer import BehaviorAnalyzer
from modules.threat_classifier import ThreatClassifier
from modules.report import AIReport

def main():
    parser = argparse.ArgumentParser(description="Shadow AI Engine - Threat Detection")
    parser.add_argument("input", help="CSV log file or directory")
    parser.add_argument("--mode", choices=["anomaly", "behavior", "classify", "full"], default="full")
    parser.add_argument("--output", default="ai_threat_report.html")
    args = parser.parse_args()

    print(f"[*] Shadow AI Engine starting on: {args.input}")
    results = {}

    if args.mode in ["anomaly", "full"]:
        detector = AnomalyDetector(args.input)
        results["anomalies"] = detector.detect()

    if args.mode in ["behavior", "full"]:
        analyzer = BehaviorAnalyzer(args.input)
        results["behaviors"] = analyzer.analyze()

    if args.mode in ["classify", "full"]:
        classifier = ThreatClassifier(results.get("anomalies", []))
        results["threats"] = classifier.classify()

    report = AIReport(args.input, results)
    report.save(args.output)
    print(f"[+] Report saved: {args.output}")

if __name__ == "__main__":
    main()
