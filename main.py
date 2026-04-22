#!/usr/bin/env python3
"""
shadow-ai-engine - AI-Powered Threat Detection & Anomaly Analysis Engine
Uses ML models to detect network anomalies and classify threats
"""
import argparse
from modules.anomaly_detector import AnomalyDetector
from modules.threat_classifier import ThreatClassifier
from modules.network_profiler import NetworkProfiler
from modules.report import AIReport

def main():
    parser = argparse.ArgumentParser(description="Shadow AI Engine")
    parser.add_argument("--pcap", help="PCAP file to analyze")
    parser.add_argument("--log", help="Log file to analyze")
    parser.add_argument("--train", action="store_true", help="Train anomaly model")
    parser.add_argument("--output", default="ai_report.html")
    args = parser.parse_args()

    results = {}

    if args.log:
        print(f"[*] Loading log data: {args.log}")
        profiler = NetworkProfiler(args.log)
        profile = profiler.build_profile()
        results["profile"] = profile

        detector = AnomalyDetector(profile)
        if args.train:
            detector.train()
        anomalies = detector.detect()
        results["anomalies"] = anomalies

        classifier = ThreatClassifier()
        results["threats"] = classifier.classify(anomalies)

    report = AIReport(results)
    report.save(args.output)
    print(f"[+] AI Analysis complete. Report: {args.output}")

if __name__ == "__main__":
    main()
