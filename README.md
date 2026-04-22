# shadow-ai-engine 🤖

AI-Powered Threat Detection & Anomaly Analysis Engine

## Features
- Statistical anomaly detection (Z-score on traffic logs)
- Rule-based traffic classification (port scan, SQLi, XSS, DDoS, brute force)
- Threat scoring system (0-100)
- JSON report export

## Usage
```bash
pip install -r requirements.txt
python main.py --input network_logs.csv --mode full
python main.py --input access.csv --mode anomaly
```

## Input Format (CSV)
```
src_ip,dest_port,bytes,flags,payload,status,count,pkt_count
192.168.1.1,80,1024,S,,200,5,100
```
