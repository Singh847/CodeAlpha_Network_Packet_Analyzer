# 🛡️ CodeAlpha Cybersecurity Internship

<div align="center">

![Kali Linux](https://img.shields.io/badge/Kali-Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Sniffer-00897B?style=for-the-badge)
![Suricata](https://img.shields.io/badge/Suricata-IDS-EF3B2D?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Completed-success?style=for-the-badge)
![GitHub](https://img.shields.io/badge/GitHub-Singh847-181717?style=for-the-badge&logo=github)

**Intern:** Singh847
**Domain:** Cyber Security
**Company:** [CodeAlpha](https://www.codealpha.tech)
**Platform:** Kali Linux

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Project Structure](#-project-structure)
- [Task 1 — Basic Network Sniffer](#-task-1--basic-network-sniffer)
- [Task 4 — Network Intrusion Detection System](#-task-4--network-intrusion-detection-system)
- [Combined Dashboard](#-combined-dashboard-task-1--task-4)
- [Installation](#-installation)
- [Usage](#-usage)
- [Attack Simulations](#-attack-simulations-for-demo)
- [What I Learned](#-what-i-learned)
- [Contact](#-contact)

---

## 🔍 Overview

This repository contains my completed projects for the **CodeAlpha Cybersecurity Internship**. I built two powerful network security tools that work together as a complete **network monitoring and threat detection solution** — all running on **Kali Linux**.

| Tool | Purpose | Technology |
|------|---------|------------|
| 🔍 Network Sniffer | Capture & analyze live packets | Python, Scapy |
| 🚨 IDS | Detect attacks & intrusions | Suricata, Python |
| 🖥️ Combined Dashboard | Unified real-time terminal view | Curses, Threading |

---

## 📁 Project Structure

```
CodeAlpha_ProjectName/
│
├── 📄 packet_analyzer.py          # Task 1 — Basic packet analyzer
├── 📄 packet_analyzer_v2.py       # Task 1 — Advanced TUI dashboard
│
├── 📁 Task4_IDS/
│   ├── ids_dashboard.py           # Task 4 — IDS alert dashboard
│   ├── codealpha.rules            # Task 4 — 23 custom Suricata rules
│   ├── eve.json                   # Task 4 — Suricata detailed logs
│   └── ids_report.txt             # Task 4 — Auto-generated report
│
├── 📁 Combined_Dashboard/
│   └── combined_dashboard.py      # Task 1 + Task 4 unified dashboard
│
└── 📄 README.md
```

---

## 🔧 Task 1 — Basic Network Sniffer

> Real-time network packet analyzer built with **Python + Scapy**

### ✨ Features

- 📡 Live packet capture on any network interface
- 🔍 Protocol detection: **TCP, UDP, ICMP, HTTP, HTTPS, DNS, FTP, SSH, ARP**
- 📊 Source & destination IP and port analysis
- 📦 Deep packet inspection & payload decoding
- 📈 Real-time session statistics
- 🚨 Built-in **live port scan detection**
- 🖥️ Interactive **TUI dashboard** with 4 tabs:

| Tab | Content |
|-----|---------|
| 1️⃣ Packets | Live packet stream |
| 2️⃣ Deep-Dive | HTTP/DNS/TLS/FTP/SMTP content |
| 3️⃣ Graphs | Sparkline + bar charts |
| 4️⃣ Alerts | Security alerts |

### 🛠️ Tools & Libraries

```
Python 3  |  Scapy  |  Curses  |  Socket  |  Threading
```

### ▶️ Run

```bash
# Basic analyzer
sudo python3 packet_analyzer.py

# Advanced TUI dashboard
sudo python3 packet_analyzer_v2.py

# On specific interface
sudo python3 packet_analyzer_v2.py -i eth0

# With BPF filter
sudo python3 packet_analyzer_v2.py -f "tcp port 80 or udp port 53"
```

### 📊 Sample Output

```
#00001  04:27:37  [ HTTPS ]
  SRC  10.0.2.15:38158  →  DST  34.49.51.44:443
  INFO Flags=PA  Seq=4019687352  Win=63022
  SIZE 93 bytes
────────────────────────────────────────────
SESSION SUMMARY
  Duration      : 12.9 s
  Total Packets : 64
  Total Bytes   : 4,259
  TCP  ████████████████████  34
  HTTPS████████████████████  30
```

---

## 🚨 Task 4 — Network Intrusion Detection System

> Full IDS powered by **Suricata** with **23 custom detection rules**

### ✨ Features

- 🔴 Real-time intrusion detection
- 📋 **23 custom rules** across 5 attack categories
- 🐍 Python dashboard for alert visualization
- 📊 Alert summary with top attacking IPs
- 💾 JSON + text log output
- 🔄 Auto-refreshing live monitor

### 🛡️ Detection Categories

| Category | Rules | Examples |
|----------|-------|---------|
| 🔍 Reconnaissance | 5 | Ping sweep, SYN/NULL/FIN/XMAS scan |
| 💥 Brute Force | 4 | SSH, FTP, RDP, Telnet |
| 🌊 DoS Attacks | 4 | ICMP flood, SYN flood, Ping of Death, UDP flood |
| 🌐 Web Attacks | 5 | SQL injection, XSS, Directory traversal |
| 🦠 Malware & Exfil | 5 | Metasploit, Botnet C2, Data exfiltration |

### 🛠️ Tools & Libraries

```
Suricata 8.0.4  |  Python 3  |  JSON  |  Custom Rules Engine
```

### ▶️ Run

```bash
# Step 1: Start Suricata IDS
sudo suricata -c /etc/suricata/suricata.yaml -i lo \
  -l /root/CodeAlpha_ProjectName/Task4_IDS/

# Step 2: Watch live alerts
sudo tail -f Task4_IDS/fast.log

# Step 3: Run Python dashboard
sudo python3 Task4_IDS/ids_dashboard.py

# Step 4: Auto-refresh every 5 seconds
watch -n 5 sudo python3 Task4_IDS/ids_dashboard.py
```

### 📊 Sample Alert Output

```
╔══════════════════════════════════════════════════════╗
║     CodeAlpha - Network IDS Dashboard                ║
║     Task 4 | Powered by Suricata                     ║
╚══════════════════════════════════════════════════════╝

  🕒 Time         : 2026-03-29 20:19:20
  🚨 Total Alerts : 23

  🔥 Top Alert Signatures:
  [  8x] [CodeAlpha] Nmap SYN Port Scan
  [  5x] [CodeAlpha] ICMP Ping Sweep
  [  3x] [CodeAlpha] Ping of Death
  [  2x] [CodeAlpha] SSH Brute Force

  🟡 LOW | 2026-03-29 20:11:39
  127.0.0.1 → 127.0.0.1
  └─ [CodeAlpha] Metasploit Port Detected
```

---

## 🖥️ Combined Dashboard (Task 1 + Task 4)

> Unified real-time terminal dashboard combining **both tools in one**

### ✨ Features

- 5 tabs combining Task 1 + Task 4 in one view
- ⚡ Updates every 0.15 seconds
- 🧵 Multi-threaded: sniffer + IDS reader simultaneously
- 🎨 Color-coded by protocol and threat severity

| Tab | Content |
|-----|---------|
| 1️⃣ Packets | Task 1 live packet stream |
| 2️⃣ Deep-Dive | HTTP/DNS/TLS protocol analysis |
| 3️⃣ Graphs | Traffic sparkline + bar charts |
| 4️⃣ Alerts | Live port scan + Suricata alerts |
| 5️⃣ IDS Dashboard | Task 4 full Suricata summary |

### 🎮 Controls

| Key | Action |
|-----|--------|
| `1` `2` `3` `4` `5` | Switch tabs |
| `Tab` / `→` | Next tab |
| `←` | Previous tab |
| `Q` | Quit |

### ▶️ Run

```bash
# Run on loopback (for testing)
sudo python3 Combined_Dashboard/combined_dashboard.py -i lo

# Run on ethernet
sudo python3 Combined_Dashboard/combined_dashboard.py -i eth0

# List interfaces
sudo python3 Combined_Dashboard/combined_dashboard.py --list-interfaces
```

---

## ⚙️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Singh847/CodeAlpha_ProjectName.git
cd CodeAlpha_ProjectName
```

### 2. Install Python Dependencies

```bash
pip3 install scapy --break-system-packages
```

### 3. Install Suricata

```bash
sudo apt update
sudo apt install suricata nmap -y
suricata --version
```

### 4. Copy IDS Rules

```bash
sudo mkdir -p /var/lib/suricata/rules
sudo cp Task4_IDS/codealpha.rules /var/lib/suricata/rules/
```

### 5. Configure Suricata

```bash
sudo nano /etc/suricata/suricata.yaml
# Set: default-rule-path: /var/lib/suricata/rules
# Set: rule-files: - codealpha.rules
# Set: HOME_NET: "[192.168.0.0/16,10.0.0.0/8,127.0.0.0/8]"
```

### 6. Test Configuration

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
# Should show: 23 rules successfully loaded, 0 rules failed
```

---

## ▶️ Usage

### Quick Start — All Tools

```bash
# Terminal 1: Start Suricata
sudo suricata -c /etc/suricata/suricata.yaml -i lo \
  -l /root/CodeAlpha_ProjectName/Task4_IDS/

# Terminal 2: Launch Combined Dashboard
sudo python3 Combined_Dashboard/combined_dashboard.py -i lo

# Terminal 3: Generate test traffic
nmap -sS 127.0.0.1
ping -c 20 127.0.0.1
```

---

## 💥 Attack Simulations for Demo

```bash
# Reconnaissance
nmap -sS 127.0.0.1          # SYN port scan
nmap -sN 127.0.0.1          # NULL scan
nmap -sF 127.0.0.1          # FIN scan
nmap -sX 127.0.0.1          # XMAS scan

# DoS Simulation
ping -c 100 127.0.0.1       # ICMP flood
ping -s 1500 -c 5 127.0.0.1 # Ping of Death

# Brute Force Simulation
nmap -p 22 127.0.0.1        # SSH scan
nmap -p 21 127.0.0.1        # FTP scan
nmap -p 3389 127.0.0.1      # RDP scan

# Web Attacks
curl "http://localhost/?id='+OR+'1'='1"
curl "http://localhost/?q=<script>alert(1)</script>"
curl "http://localhost/../../etc/passwd"
```

---

## 📚 What I Learned

### Technical Skills
- ✅ TCP/IP packet structure and network layers
- ✅ Real-time traffic capture with **Scapy**
- ✅ Writing 23 custom **Suricata IDS rules**
- ✅ Detecting reconnaissance, DoS, brute force, web attacks
- ✅ Building multi-threaded terminal dashboards with **Python curses**
- ✅ Network security monitoring best practices
- ✅ Log analysis and threat visualization

### Security Concepts
- ✅ Network protocol analysis (TCP, UDP, ICMP, DNS, HTTP)
- ✅ Intrusion detection vs prevention systems
- ✅ Attack signatures and rule-based detection
- ✅ Port scanning techniques (SYN, NULL, FIN, XMAS)
- ✅ DoS attack patterns and detection thresholds
- ✅ Web attack vectors (SQLi, XSS, directory traversal)
- ✅ Live threat monitoring and alerting

---

## 📞 Contact

<div align="center">

| | |
|--|--|
| 🌐 Website | [www.codealpha.tech](https://www.codealpha.tech) |
| 💬 WhatsApp | +91 9336576683 |
| 📧 Email | services@codealpha.tech |

---

*Built with ❤️ during CodeAlpha Cybersecurity Internship on Kali Linux*

</div>
---

## 📸 Screenshots

### 🔍 Task 1 — Basic Network Sniffer
![Task1 Basic](screenshots/task1_basic.png)

---

### 🖥️ Task 1 — Advanced TUI Dashboard
![Task1 Dashboard](screenshots/task1_dashboard.png)

---

### 🚨 Task 4 — IDS Dashboard (Suricata)
![Task4 IDS](screenshots/task4_ids.png)

---

### 💥 Attack Simulations
![Attacks](screenshots/attacks.png)
```

---

## 👉 STEP 4 — Save & Exit
```
Ctrl+O → Enter → Ctrl+X
