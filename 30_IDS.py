from scapy.all import sniff, ARP, IP
from datetime import datetime

# Known gateway MAC (replace with your real gateway MAC if known)
KNOWN_GATEWAY_IP = "192.168.1.1"
KNOWN_GATEWAY_MAC = None  # Will be learned on first ARP reply

LOG_FILE = "ids_alerts.log"

def arp_monitor(pkt):
    """Monitor ARP packets to detect spoofing"""
    global KNOWN_GATEWAY_MAC
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc

        if src_ip == KNOWN_GATEWAY_IP:
            if KNOWN_GATEWAY_MAC is None:
                KNOWN_GATEWAY_MAC = src_mac
                print(f"[INFO] Learned gateway MAC: {KNOWN_GATEWAY_MAC}")
            elif src_mac.lower() != KNOWN_GATEWAY_MAC.lower():
                alert = f"[ALERT] ARP Spoof! {src_ip} is claiming MAC {src_mac}, expected {KNOWN_GATEWAY_MAC}"
                print(alert)
                with open(LOG_FILE, "a") as f:
                    f.write(f"{datetime.now()} - {alert}\n")

def ip_monitor(pkt):
    """Log all IP packets"""
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        length = len(pkt)
        log_entry = f"{datetime.now()} | {src} -> {dst} | Proto: {proto} | {length} bytes"
        print(log_entry)
        with open(LOG_FILE, "a") as f:
            f.write(log_entry + "\n")

if __name__ == "__main__":
    print("Starting Local IDS Simulator...")
    print(f"Logging suspicious activity and packets to {LOG_FILE}")
    print("Press Ctrl+C to stop.\n")

    # Monitor ARP packets and IP packets simultaneously
    sniff(prn=lambda pkt: (arp_monitor(pkt), ip_monitor(pkt)), store=False, count=20)

    print("\nIDS simulation finished. Check ids_alerts.log for details.")
