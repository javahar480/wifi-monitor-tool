
# Wi-Fi Monitoring Tool (CLI-Based)

A lightweight, terminal-based Python tool to monitor devices on a local network. Built for companies that need visibility into LAN traffic without the overhead of web dashboards or commercial network monitoring tools.

---

## 🔍 Features

- 🔎 Scans multiple interfaces (`eth0`, `wlan0`) for active devices  
- 🌐 Monitors DNS and HTTP traffic in real time using Scapy  
- 🚨 Alerts when unknown MAC addresses are detected (via whitelist)  
- 🧾 Logs to plain text files for review or SIEM ingestion  
- 💻 CLI-only — fast, no GUI required  

---

## 📂 Project Structure

wifi_monitor_tool/
├── monitor.py # Main launcher
├── scanner.py # Device discovery + unknown device detection
├── traffic_monitor.py # DNS and HTTP sniffing
├── config.py # Settings: interfaces, whitelist, paths
├── network_log.txt # Output log of DNS/HTTP traffic
├── alerts.txt # Output log of unknown device alerts
├── README.md # Project documentation
└── .gitignore # Git exclusions


---

## ⚙️ Requirements

- Python 3.6+
- `scapy`
- `psutil`
- Root privileges (required for packet sniffing)

### Install dependencies:

```bash
sudo apt update
sudo apt install python3-pip net-tools tcpdump
sudo pip3 install scapy psutil --break-system-packages

🚀 Usage
Edit config.py:
Network interfaces

INTERFACES = ["eth0", "wlan0"]

Whitelisted MAC addresses

WHITELISTED_MACS = {
    "00:00:00:00:00:00",  # Replace with your device's real MAC
    "aa:bb:cc:dd:ee:ff",  # Replace with another trusted device
}

Log file names

LOG_FILE = "network_log.txt"
ALERT_LOG = "alerts.txt"

Run the monitor:

sudo python3 monitor.py

View logs:

tail -f network_log.txt
tail -f alerts.txt

🧪 Testing Tips

    Use macchanger to spoof a MAC and test unknown device alerts:

sudo macchanger -m 00:11:22:33:44:55 eth0

    Temporarily remove a known MAC from the whitelist to simulate an alert.

📄 License

This project is licensed under the MIT License.
💬 Credits & Thanks

Developed by Ichigo (2025)
Built with: Python, Scapy, psutil
Use responsibly — monitor only authorized networks.
⚖️ License Reminder

This project is released under the MIT License.
You're free to use or modify it with credit.
If you use it commercially or as a base project, attribution is required.


---

### 📌 Want this saved as a `README.md` again or ready for LinkedIn formatting?  
Let me know and I’ll package it for you!

