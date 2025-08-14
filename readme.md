# 🛡 Wi-Fi Monitoring Tool (CLI-Based with Threat Intelligence)

A lightweight, terminal-based Python tool to monitor devices and DNS activity on a local network — now with **VirusTotal integration** to detect malicious domains in real time.  
Built for sysadmins, security analysts, and power users who want visibility into LAN activity without the overhead of web dashboards or heavy commercial tools.

---

## 🔍 Features

- **Device Monitoring (ARP Scanning)**
  - Scans multiple interfaces (`eth0`, `wlan0`, etc.) for active devices
  - Alerts when unknown MAC addresses are detected (via whitelist in `config.py`)

- **DNS Monitoring + Threat Intelligence**
  - Captures DNS requests in real time using Scapy
  - Queries **VirusTotal** to check domain reputation
  - Highlights malicious domains in **red** in terminal output
  - Caches results to avoid re-checking the same domain

- **Logging**
  - Logs device alerts and DNS activity to text files
  - Output can be ingested into SIEM or log analysis tools

- **CLI-Only**
  - Runs in terminal — no GUI, no overhead

---

## 📂 Project Structure

wifi_monitor_tool/
├── monitor.py # Main launcher (runs both device + DNS monitors)
├── scanner.py # Device discovery & unknown device detection
├── traffic_monitor.py # DNS sniffing + VirusTotal domain checks
├── config.py # Settings: interfaces, whitelist, file paths
├── network_log.txt # DNS/HTTP traffic log
├── alerts.txt # Alerts for unknown devices and malicious domains
├── README.md # Project documentation
└── LICENSE # License file

yaml
Copy
Edit

---

## ⚙ Requirements

- **OS:** Linux (tested on Arch Linux KDE)
- **Python:** 3.6+
- **Dependencies:**
  - `scapy`
  - `psutil`
  - `requests`
- **Root privileges** required for packet sniffing

---

## 📥 Installation

**On Arch Linux:**
```bash
sudo pacman -Syu python-pip net-tools tcpdump macchanger
pip3 install scapy psutil requests
🔑 VirusTotal API Key Setup
Go to https://www.virustotal.com/gui/join-us

Sign up for a free account

Verify your email and log in

Click your profile icon → API key

Copy the key and paste it into traffic_monitor.py:

python
Copy
Edit
API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
🛠 Configuration
Edit config.py:

python
Copy
Edit
INTERFACES = ["eno1", "wlo1"]  # Use `ip link` to find your real interfaces

WHITELISTED_MACS = {
    "xx:xx:xx:xx:xx:xx",  # Ethernet MAC
    "yy:yy:yy:yy:yy:yy",  # Wi-Fi MAC
}

LOG_FILE = "network_log.txt"
ALERT_LOG = "alerts.txt"
🚀 Usage
Run both monitors:

bash
Copy
Edit
sudo python3 monitor.py
View logs in real time:

bash
Copy
Edit
tail -f network_log.txt
tail -f alerts.txt
🧪 Testing
Simulate an Unknown Device:

bash
Copy
Edit
sudo macchanger -m 00:11:22:33:44:55 wlo1
Simulate a Malicious Domain:

Visit a domain flagged by VirusTotal from any device on your LAN.

Check terminal for [MALICIOUS] alerts.

⚠ License Reminder
This project is licensed under the MIT License.
You are free to use and modify it, but monitor only authorized networks.

💬 Credits
Developed by Ichigo (2025)
Built with: Python, Scapy, Psutil, Requests, VirusTotal API

yaml
Copy
Edit

---

Do you want me to also **add screenshots and example output logs** to the README so it looks professional and showcase-ready for GitHub? That would make it stand out.




You said:
give me as one file


ChatGPT said:
Here’s the complete README.md as a single ready-to-save file:

markdown
Copy
Edit
# 🛡 Wi-Fi Monitoring Tool (CLI-Based with Threat Intelligence)

A lightweight, terminal-based Python tool to monitor devices and DNS activity on a local network — now with **VirusTotal integration** to detect malicious domains in real time.  
Built for sysadmins, security analysts, and power users who want visibility into LAN activity without the overhead of web dashboards or heavy commercial tools.

---

## 🔍 Features

- **Device Monitoring (ARP Scanning)**
  - Scans multiple interfaces (`eth0`, `wlan0`, etc.) for active devices
  - Alerts when unknown MAC addresses are detected (via whitelist in `config.py`)

- **DNS Monitoring + Threat Intelligence**
  - Captures DNS requests in real time using Scapy
  - Queries **VirusTotal** to check domain reputation
  - Highlights malicious domains in **red** in terminal output
  - Caches results to avoid re-checking the same domain

- **Logging**
  - Logs device alerts and DNS activity to text files
  - Output can be ingested into SIEM or log analysis tools

- **CLI-Only**
  - Runs in terminal — no GUI, no overhead

---

## 📂 Project Structure

wifi_monitor_tool/
├── monitor.py # Main launcher (runs both device + DNS monitors)
├── scanner.py # Device discovery & unknown device detection
├── traffic_monitor.py # DNS sniffing + VirusTotal domain checks
├── config.py # Settings: interfaces, whitelist, file paths
├── network_log.txt # DNS/HTTP traffic log
├── alerts.txt # Alerts for unknown devices and malicious domains
├── README.md # Project documentation
└── LICENSE # License file

yaml
Copy
Edit

---

## ⚙ Requirements

- **OS:** Linux (tested on Arch Linux KDE)
- **Python:** 3.6+
- **Dependencies:**
  - `scapy`
  - `psutil`
  - `requests`
- **Root privileges** required for packet sniffing

---

## 📥 Installation

**On Arch Linux:**
```bash
sudo pacman -Syu python-pip net-tools tcpdump macchanger
pip3 install scapy psutil requests
🔑 VirusTotal API Key Setup
Go to https://www.virustotal.com/gui/join-us

Sign up for a free account

Verify your email and log in

Click your profile icon → API key

Copy the key and paste it into traffic_monitor.py:

python
Copy
Edit
API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
🛠 Configuration
Edit config.py:

python
Copy
Edit
INTERFACES = ["eno1", "wlo1"]  # Use `ip link` to find your real interfaces

WHITELISTED_MACS = {
    "xx:xx:xx:xx:xx:xx",  # Ethernet MAC
    "yy:yy:yy:yy:yy:yy",  # Wi-Fi MAC
}

LOG_FILE = "network_log.txt"
ALERT_LOG = "alerts.txt"
🚀 Usage
Run both monitors:

bash
Copy
Edit
sudo python3 monitor.py
View logs in real time:

bash
Copy
Edit
tail -f network_log.txt
tail -f alerts.txt
🧪 Testing
Simulate an Unknown Device:

bash
Copy
Edit
sudo macchanger -m 00:11:22:33:44:55 wlo1
Simulate a Malicious Domain:

Visit a domain flagged by VirusTotal from any device on your LAN.

Check terminal for [MALICIOUS] alerts.

⚠ License Reminder
This project is licensed under the MIT License.
You are free to use and modify it, but monitor only authorized networks.

💬 Credits
Developed by Ichigo (2025)
Built with: Python, Scapy, Psutil, Requests, VirusTotal API

yaml
Copy
Edit

---

Do you want me to also **add colored example output logs** in the README so that people see exactly what an alert looks like when they run it? That would make it even more engaging.





You said:
developed by javahar


ChatGPT said:
Got it — here’s your updated README.md with the credit changed.

markdown
Copy
Edit
# 🛡 Wi-Fi Monitoring Tool (CLI-Based with Threat Intelligence)

A lightweight, terminal-based Python tool to monitor devices and DNS activity on a local network — now with **VirusTotal integration** to detect malicious domains in real time.  
Built for sysadmins, security analysts, and power users who want visibility into LAN activity without the overhead of web dashboards or heavy commercial tools.

---

## 🔍 Features

- **Device Monitoring (ARP Scanning)**
  - Scans multiple interfaces (`eth0`, `wlan0`, etc.) for active devices
  - Alerts when unknown MAC addresses are detected (via whitelist in `config.py`)

- **DNS Monitoring + Threat Intelligence**
  - Captures DNS requests in real time using Scapy
  - Queries **VirusTotal** to check domain reputation
  - Highlights malicious domains in **red** in terminal output
  - Caches results to avoid re-checking the same domain

- **Logging**
  - Logs device alerts and DNS activity to text files
  - Output can be ingested into SIEM or log analysis tools

- **CLI-Only**
  - Runs in terminal — no GUI, no overhead

---

## 📂 Project Structure

wifi_monitor_tool/
├── monitor.py # Main launcher (runs both device + DNS monitors)
├── scanner.py # Device discovery & unknown device detection
├── traffic_monitor.py # DNS sniffing + VirusTotal domain checks
├── config.py # Settings: interfaces, whitelist, file paths
├── network_log.txt # DNS/HTTP traffic log
├── alerts.txt # Alerts for unknown devices and malicious domains
├── README.md # Project documentation
└── LICENSE # License file

yaml
Copy
Edit

---

## ⚙ Requirements

- **OS:** Linux (tested on Arch Linux KDE)
- **Python:** 3.6+
- **Dependencies:**
  - `scapy`
  - `psutil`
  - `requests`
- **Root privileges** required for packet sniffing

---

## 📥 Installation

**On Arch Linux:**
```bash
sudo pacman -Syu python-pip net-tools tcpdump macchanger
pip3 install scapy psutil requests
🔑 VirusTotal API Key Setup
Go to https://www.virustotal.com/gui/join-us

Sign up for a free account

Verify your email and log in

Click your profile icon → API key

Copy the key and paste it into traffic_monitor.py:

python
Copy
Edit
API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
🛠 Configuration
Edit config.py:

python
Copy
Edit
INTERFACES = ["eno1", "wlo1"]  # Use `ip link` to find your real interfaces

WHITELISTED_MACS = {
    "xx:xx:xx:xx:xx:xx",  # Ethernet MAC
    "yy:yy:yy:yy:yy:yy",  # Wi-Fi MAC
}

LOG_FILE = "network_log.txt"
ALERT_LOG = "alerts.txt"
🚀 Usage
Run both monitors:

bash
Copy
Edit
sudo python3 monitor.py
View logs in real time:

bash
Copy
Edit
tail -f network_log.txt
tail -f alerts.txt
🧪 Testing
Simulate an Unknown Device:

bash
Copy
Edit
sudo macchanger -m 00:11:22:33:44:55 wlo1
Simulate a Malicious Domain:

Visit a domain flagged by VirusTotal from any device on your LAN.

Check terminal for [MALICIOUS] alerts.

⚠ License Reminder
This project is licensed under the MIT License.
You are free to use and modify it, but monitor only authorized networks.

💬 Credits
Developed by Javahar (2025)
Built with: Python, Scapy, Psutil, Requests, VirusTotal API



