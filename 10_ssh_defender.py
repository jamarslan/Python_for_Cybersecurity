#!/usr/bin/env python3
# Simple SSH attack detector - fixed version

# Configuration
log_file = "/var/log/auth.log"  # Path to your auth log
max_attempts = 5                # Number of failed attempts before alert

def main():
    print("Checking for SSH attacks...")
    
    try:
        # Count failed attempts per IP
        ip_count = {}
        
        with open(log_file) as f:
            for line in f:
                if "Failed password" in line and "ssh" in line:
                    # Extract IP address
                    ip_start = line.find("from ") + 5
                    ip_end = line.find(" port")
                    ip = line[ip_start:ip_end]
                    
                    # Update count
                    ip_count[ip] = ip_count.get(ip, 0) + 1
        
        # Show results
        print("\nSuspicious IPs:")
        for ip, count in ip_count.items():
            if count >= max_attempts:
                print(f"- {ip} ({count} failed attempts)")
    
    except FileNotFoundError:
        print(f"Error: Could not find {log_file}")
        print("Try running with sudo: sudo ./10_ssh_defender.py")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()