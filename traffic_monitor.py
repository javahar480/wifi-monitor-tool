from scapy.all import sniff, DNS, DNSQR, IP
import requests
import time
from config import INTERFACES

API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # Get from https://www.virustotal.com/gui/join-us
checked_domains = {}

def check_domain_reputation(domain):
    if domain in checked_domains:
        return checked_domains[domain]

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": API_KEY}

    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            malicious_count = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            if malicious_count > 0:
                result = f"[MALICIOUS] {malicious_count} engines flagged this domain!"
            else:
                result = "[CLEAN]"
        else:
            result = "[UNKNOWN] API limit or error"
    except Exception as e:
        result = f"[ERROR] {e}"

    checked_domains[domain] = result
    time.sleep(1)
    return result

def process_packet(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        src_ip = packet[IP].src
        domain_name = packet[DNSQR].qname.decode("utf-8").rstrip('.')
        reputation = check_domain_reputation(domain_name)

        if "[MALICIOUS]" in reputation:
            print(f"\033[91m[DNS] {src_ip} -> {domain_name} {reputation}\033[0m")
        else:
            print(f"[DNS] {src_ip} -> {domain_name} {reputation}")

def run_traffic_sniffer():
    for iface in INTERFACES:
        try:
            print(f"[*] Starting DNS monitor on {iface}...")
            sniff(filter="udp port 53", prn=process_packet, iface=iface, store=False)
        except Exception as e:
            print(f"[!] Failed to sniff on {iface}: {e}")
