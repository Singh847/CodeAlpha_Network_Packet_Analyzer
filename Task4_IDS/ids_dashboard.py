#!/usr/bin/env python3
"""
CodeAlpha Internship - Task 4
Network Intrusion Detection Dashboard
"""

import json
import os
from datetime import datetime
from collections import Counter

LOG_PATHS = [
    "/root/CodeAlpha_ProjectName/Task4_IDS/eve.json",
    "/var/log/suricata/eve.json"
]

def find_log():
    for path in LOG_PATHS:
        if os.path.exists(path):
            return path
    return None

def parse_alerts(log_file):
    alerts = []
    try:
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    if event.get('event_type') == 'alert':
                        alerts.append(event)
                except:
                    continue
    except:
        pass
    return alerts

def severity_label(severity):
    return {
        1: "🔴 HIGH",
        2: "🟠 MEDIUM",
        3: "🟡 LOW"
    }.get(severity, "⚪ INFO")

def display_dashboard(alerts):
    os.system('clear')
    print("""
╔══════════════════════════════════════════════════════╗
║     CodeAlpha - Network IDS Dashboard                ║
║     Task 4 | Powered by Suricata                     ║
╚══════════════════════════════════════════════════════╝
""")
    print(f"  🕒 Time         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  🚨 Total Alerts : {len(alerts)}")
    print()

    if not alerts:
        print("  ✅ No alerts yet — generating traffic...")
        print()
        print("  Run these to trigger alerts:")
        print("  → nmap -sS 127.0.0.1")
        print("  → ping -c 20 127.0.0.1")
        print("  → nmap -p 22 127.0.0.1")
        return

    # By Protocol
    protocols = [a.get('proto', 'unknown') for a in alerts]
    proto_count = Counter(protocols)
    print("  📡 Alerts by Protocol:")
    print("  " + "─"*45)
    for proto, count in proto_count.most_common():
        bar = "█" * min(count, 30)
        print(f"  {proto:<8} {bar} {count}")
    print()

    # Top Alert Signatures
    sigs = [a['alert']['signature'] for a in alerts]
    top_sigs = Counter(sigs).most_common(8)
    print("  🔥 Top Alert Signatures:")
    print("  " + "─"*45)
    for sig, count in top_sigs:
        print(f"  [{count:>4}x] {sig}")
    print()

    # Top Attacking IPs
    src_ips = [a.get('src_ip', 'unknown') for a in alerts]
    top_ips = Counter(src_ips).most_common(5)
    print("  🌐 Top Source IPs:")
    print("  " + "─"*45)
    for ip, count in top_ips:
        print(f"  {ip:<20} {count} alerts")
    print()

    # Recent 10 Alerts
    print("  🕒 Last 10 Alerts:")
    print("  " + "─"*45)
    for a in alerts[-10:]:
        ts       = a.get('timestamp', '')[:19].replace('T', ' ')
        sig      = a['alert']['signature']
        src      = a.get('src_ip', '?')
        dst      = a.get('dest_ip', '?')
        severity = a['alert'].get('severity', 3)
        print(f"  {severity_label(severity)} | {ts}")
        print(f"  {src} → {dst}")
        print(f"  └─ {sig}")
        print()

    # Save Report
    report = "/root/CodeAlpha_ProjectName/Task4_IDS/ids_report.txt"
    with open(report, 'w') as f:
        f.write(f"CodeAlpha IDS Report\n")
        f.write(f"Generated: {datetime.now()}\n")
        f.write(f"Total Alerts: {len(alerts)}\n\n")
        for sig, count in Counter(sigs).most_common():
            f.write(f"[{count}x] {sig}\n")
    print(f"  ✅ Report saved: {report}")

def main():
    log_file = find_log()
    if not log_file:
        print("\n[!] No Suricata log found!")
        print("[!] Start Suricata first:")
        print("    sudo suricata -c /etc/suricata/suricata.yaml -i lo -l /root/CodeAlpha_ProjectName/Task4_IDS/")
        return

    print(f"[*] Reading: {log_file}")
    alerts = parse_alerts(log_file)
    display_dashboard(alerts)

if __name__ == '__main__':
    main()
