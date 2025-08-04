from scapy.all import sniff, DNSQR, Raw, TCP, IP
from config import LOG_FILE

def log(msg):
    print(msg)
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

def process_packet(pkt):
    try:
        if pkt.haslayer(DNSQR):
            domain = pkt[DNSQR].qname.decode()
            src = pkt[IP].src
            log(f"[DNS] {src} -> {domain}")
        elif pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = pkt[Raw].load
            if b"Host:" in payload:
                lines = payload.split(b"\r\n")
                host_line = next((line for line in lines if b"Host:" in line), None)
                if host_line:
                    host = host_line.decode(errors="ignore")
                    log(f"[HTTP] {pkt[IP].src} -> {host}")
    except Exception:
        pass

def run_traffic_sniffer():
    sniff(filter="port 53 or port 80", prn=process_packet, store=0)

