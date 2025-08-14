from threading import Thread
from scanner import run_device_monitor
from traffic_monitor import run_traffic_sniffer

if __name__ == "__main__":
    print("[*] Starting network monitoring...")
    t1 = Thread(target=run_device_monitor)
    t2 = Thread(target=run_traffic_sniffer)

    t1.start()
    t2.start()

    t1.join()
    t2.join()
