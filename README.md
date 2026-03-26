Network Packet Analyzer (CodeAlpha Internship - Task 1)

A real-time network traffic analyzer with deep packet inspection, live visualization, and built-in security detection.

📌 Project Overview

This project is a high-performance Network Packet Analyzer developed as part of my Cybersecurity Internship at CodeAlpha. It provides real-time visibility into network traffic, enabling inspection of protocols, payloads, and potential security anomalies.

The project includes two versions:

packet_analyzer.py
A lightweight CLI-based packet sniffer with protocol color-coding and session summaries.
packet_analyzer_v2.py
An advanced interactive terminal dashboard using curses, featuring live graphs, deep packet inspection, and security alerts.
🚀 Key Features
🔎 Multi-Protocol Support
TCP, UDP, ICMP, ARP, DNS, IPv4/IPv6
📊 Live Dashboard (v2)
Real-time packet rate graphs and traffic distribution
🔬 Deep Packet Inspection
Extracts:
HTTP requests/responses
DNS queries and answers
TLS handshake (including SNI)
SMTP & FTP commands
⚠️ Security Monitoring
Detects SYN-based port scanning
Highlights suspicious traffic patterns
⚙️ Dual Capture Engine
Uses Scapy (full decoding)
Raw socket fallback (Linux)
🛠️ Technical Stack
Language: Python 3.x
Core Library: Scapy
UI Framework: Curses (v2 dashboard)
Platform: Kali Linux / Debian-based systems
📋 Prerequisites
Python 3.8+
Root/Administrator privileges
Linux-based OS (recommended)
⚙️ Installation
1. Clone Repository
git clone https://github.com/Singh847/CodeAlpha_Network_Packet_Analyzer.git
cd CodeAlpha_Network_Packet_Analyzer
2. Install Dependencies
pip install scapy
▶️ Usage
🔹 CLI Packet Analyzer
sudo python3 packet_analyzer.py
Options
-i, --iface        Network interface
-c, --count        Number of packets to capture
-f, --filter       BPF filter (e.g. "tcp port 80")
-v, --verbose      Show payload data
--list-interfaces  Show interfaces
--no-colour        Disable colors
Example
sudo python3 packet_analyzer.py -i eth0 -c 100 -f "tcp port 80" -v
🔹 Interactive Dashboard (v2)
sudo python3 packet_analyzer_v2.py
Options
-i, --iface     Network interface
-c, --count     Stop after N packets
-f, --filter    BPF filter
🎮 Dashboard Controls
Key	Action
1	Packets View
2	Deep-Dive
3	Graphs
4	Alerts
← / → / Tab	Switch tabs
q	Quit
📊 Dashboard Modules
📦 Packets Tab
Live packet stream
Displays source, destination, protocol, size, and metadata
🔬 Deep-Dive Tab
HTTP → methods, headers
DNS → queries & responses
TLS → handshake + SNI
FTP/SMTP → commands
📈 Graphs Tab
Packets per second (sparkline)
Protocol distribution
Top ports and IPs
⚠️ Alerts Tab
Detects port scanning (SYN flood behavior)
Displays real-time warnings
🧠 Project Architecture
Network Interface
        │
   Packet Capture
        │
 ┌──────┴────────┐
 │               │
Scapy       Raw Socket
 │               │
 └──────┬────────┘
        │
 Packet Processing
        │
 ┌──────┼─────────────┐
 │      │             │
Parsing Stats   Deep Inspection
 │      │             │
 └──────┴─────────────┘
        │
   Output Layer
 (CLI / Dashboard)
🔐 Security Features
Port scan detection using SYN tracking
Real-time anomaly visibility
Payload inspection for suspicious data
⚠️ Limitations
Requires sudo privileges
Raw socket fallback:
Linux only
Limited protocol parsing
Not designed for high-throughput enterprise environments
🚧 Future Improvements
PCAP file export/import
Web-based dashboard (Flask/React)
GeoIP visualization
AI-based anomaly detection
Plugin-based protocol extensions
📸 Screenshots

(Add screenshots here for better presentation)

Example:

CLI Output
Dashboard (Packets / Graphs / Alerts)
🤝 Contribution

Contributions are welcome!

Fork the repository
Create a new branch
Commit changes
Submit a pull request
📜 License

MIT License

👨‍💻 Internship Context

Developed as part of the CodeAlpha Cybersecurity Internship, focusing on:

Network traffic analysis
Packet inspection
Real-time monitoring systems
Security threat detection
⭐ Acknowledgment

Special thanks to CodeAlpha for providing the opportunity to work on real-world cybersecurity projects.

📬 Contact

Feel free to connect for collaboration or feedback.
