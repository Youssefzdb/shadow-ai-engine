#!/usr/bin/env python3
"""shadow-ai-engine - AI-Powered Threat Detection & Anomaly Analysis"""
import argparse
from modules.anomaly_detector import AnomalyDetector
from modules.traffic_classifier import TrafficClassifier
from modules.threat_scorer import ThreatScorer
from modules.reporter import AIReporter

def main():
    parser = argparse.ArgumentParser(description="shadow-ai-engine - AI Threat Detection")
    parser.add_argument("--input", required=True, help="CSV log file to analyze")
    parser.add_argument("--mode", choices=["anomaly", "classify", "full"], default="full")
    parser.add_argument("--output", default="ai_report.json")
    args = parser.parse_args()

    print(f"[*] shadow-ai-engine starting | mode: {args.mode}")

    results = {}

    if args.mode in ["anomaly", "full"]:
        detector = AnomalyDetector(args.input)
        results["anomalies"] = detector.detect()

    if args.mode in ["classify", "full"]:
        classifier = TrafficClassifier(args.input)
        results["classifications"] = classifier.classify()

    scorer = ThreatScorer(results)
    results["threat_score"] = scorer.score()

    reporter = AIReporter(results)
    reporter.save(args.output)
    print(f"[+] AI analysis complete. Report: {args.output}")

if __name__ == "__main__":
    main()
