#!/usr/bin/env python3
"""shadow-ai-engine - AI-Powered Threat Detection & Anomaly Analysis"""
import argparse
from modules.feature_extractor import FeatureExtractor
from modules.anomaly_detector import AnomalyDetector
from modules.classifier import ThreatClassifier
from modules.report import Report

def main():
    parser = argparse.ArgumentParser(description="shadow-ai-engine")
    parser.add_argument("logfile", help="Network/system log file")
    parser.add_argument("--threshold", type=float, default=0.8, help="Anomaly threshold (0-1)")
    parser.add_argument("--output", default="ai_report.html")
    args = parser.parse_args()

    print(f"[*] shadow-ai-engine analyzing: {args.logfile}")
    
    extractor = FeatureExtractor(args.logfile)
    features = extractor.extract()
    print(f"[+] Extracted {len(features)} feature vectors")

    detector = AnomalyDetector(features, args.threshold)
    anomalies = detector.detect()
    print(f"[!] Detected {len(anomalies)} anomalies")

    classifier = ThreatClassifier(anomalies)
    threats = classifier.classify()

    Report(args.logfile, features, anomalies, threats).save(args.output)
    print(f"[+] Report: {args.output}")

if __name__ == "__main__":
    main()
