from scapy.all import ARP, sniff, getmacbyip
from datetime import datetime

# Store known IP->MAC mapping (simulate gateway mapping)
KNOWN_MACS = {
    "192.168.1.1": None  # Replace None with actual gateway MAC if known
}

LOG_FILE = "arp_alerts.log"

def arp_monitor_callback(pkt):
    """Check each ARP packet for spoofing attempts."""
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc

        # Skip broadcast packets
        if src_mac.lower() in ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]:
            return

        # Check for spoofing
        if src_ip in KNOWN_MACS:
            known_mac = KNOWN_MACS[src_ip]
            if known_mac is None:
                KNOWN_MACS[src_ip] = src_mac  # Initialize
            elif src_mac.lower() != known_mac.lower():
                alert = f"[!] ARP Spoof Detected! {src_ip} is claiming MAC {src_mac}, expected {known_mac}"
                print(alert)
                with open(LOG_FILE, "a") as f:
                    f.write(f"{datetime.now()} - {alert}\n")

if __name__ == "__main__":
    print("Starting ARP spoof detection (press Ctrl+C to stop)...")
    print(f"Logging suspicious ARP activity to {LOG_FILE}\n")

    # Capture 10 ARP packets for demo
    sniff(prn=arp_monitor_callback, filter="arp", count=10)
    print("\nARP monitoring complete. Check arp_alerts.log for details.")
