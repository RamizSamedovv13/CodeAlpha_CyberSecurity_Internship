TASK="Task-4_Network-Intrusion-Detection"

cat > "$TASK/README.md" <<'EOF'
# Task 4 - Network Intrusion Detection System (NIDS)

## Overview

This project implements a Network-based Intrusion Detection System
using Suricata on Kali Linux.

The system monitors network traffic, detects suspicious activity
using custom detection rules, generates security alerts and
provides a basic firewall response mechanism.

## Tools and Technologies

- Kali Linux
- Suricata 8.0.7
- Emerging Threats Open Ruleset
- Nmap
- iptables
- Linux networking utilities

## Network Configuration

- Network Interface: eth0
- Local Network: 192.168.1.0/24
- IDS Mode: Passive Detection

## Detection Capabilities

Custom detection rules include:

1. ICMP Echo Request Detection
2. TCP SYN Port Scan Detection
3. Repeated SSH Connection Attempts
4. HTTP Path Traversal Detection
5. Sensitive File Access Detection

The project also uses the Emerging Threats Open ruleset
for additional threat detection.

## Monitoring and Logging

Suricata continuously monitors network traffic and generates:

- fast.log - Human-readable security alerts
- eve.json - Structured JSON event logs
- stats.log - Network and engine statistics

## Response Mechanism

Two scripts are provided:

- scripts/block-ip.sh
- scripts/unblock-ip.sh

They allow an administrator to manually block or unblock
an IP address using iptables.

The IDS operates in passive detection mode.
Firewall blocking is a separate manual response action.

## Testing

The following tests are performed in an authorized lab:

- ICMP traffic generation using ping
- TCP port scanning using Nmap
- Custom detection rule validation
- Security alert verification

## Project Structure

```text
Task-4_Network-Intrusion-Detection/
├── README.md
├── rules/
│   └── local.rules
├── config/
│   └── README.md
├── logs/
│   ├── alerts-sample.json
│   ├── fast-sample.log
│   └── stats-sample.log
├── screenshots/
└── scripts/
    ├── block-ip.sh
    └── unblock-ip.sh
