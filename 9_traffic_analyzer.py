from scapy.all import *
from datetime import datetime
import time
import sys

def analyze_packet(pkt):
    try:
        # ARP Spoof Detection (Fixed)
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP Reply
            # Skip broadcast and zero MACs
            if pkt[ARP].hwsrc in ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]:
                return
            
            real_mac = getmacbyip(pkt[ARP].psrc)
            if real_mac and real_mac.lower() != pkt[ARP].hwsrc.lower():
                alert = f"[!] ARP Spoof: {pkt[ARP].psrc} ({pkt[ARP].hwsrc}) impersonating {real_mac}"
                print(alert)
                log_alert(alert)

    except Exception as e:
        log_alert(f"[ERROR] {datetime.now()} - Packet processing: {str(e)}")

def log_alert(message):
    with open("alerts.log", "a") as f:
        f.write(f"{datetime.now()} - {message}\n")

def main():
    interface = "wlp0s20f3"  # Change to your interface
    
    # Verify interface exists
    if interface not in get_if_list():
        print(f"[!] Interface {interface} not found. Available:")
        print(get_if_list())
        sys.exit(1)

    print(f"[+] Monitoring {interface}. Press Ctrl+C to stop...")
    try:
        sniff(iface=interface, 
              prn=analyze_packet, 
              store=False,
              stop_filter=lambda x: False)  # Runs until manually stopped
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        log_alert(f"FATAL ERROR: {e}")

if __name__ == "__main__":
    main()
