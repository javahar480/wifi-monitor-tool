from scapy.all import ARP, Ether, srp
from config import WHITELISTED_MACS, ALERT_LOG, INTERFACES, SCAN_INTERVAL
import time

def scan_interface(iface):
    arp = ARP(pdst="192.168.1.0/24")
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    try:
        result = srp(packet, iface=iface, timeout=3, verbose=0)[0]
        devices = [{'ip': rcv.psrc, 'mac': rcv.hwsrc} for snd, rcv in result]
        return devices
    except Exception as e:
        print(f"[!] Failed to scan {iface}: {e}")
        return []


def check_for_intruders(devices):
    for device in devices:
        if device['mac'].lower() not in [mac.lower() for mac in WHITELISTED_MACS]:
            with open(ALERT_LOG, "a") as f:
                alert_msg = f"[ALERT] Unknown device detected: {device['ip']} - {device['mac']}\n"
                print(alert_msg.strip())
                f.write(alert_msg)

def run_device_monitor():
    while True:
        all_devices = []
        for iface in INTERFACES:
            devices = scan_interface(iface)
            all_devices.extend(devices)

        # 🔁 Deduplicate devices by MAC address
        unique_devices = {}
        for device in all_devices:
            unique_devices[device['mac']] = device

        check_for_intruders(list(unique_devices.values()))
        time.sleep(SCAN_INTERVAL)

