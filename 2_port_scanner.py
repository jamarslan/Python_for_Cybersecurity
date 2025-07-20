# port scanner
import socket

def scan_port(ip, port):
    try:
        # Try IPv4 first
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return True
        
        # Then try IPv6 if IPv4 fails (for localhost cases)
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
        
    except socket.gaierror:  # Handle DNS/address errors
        return False
    except:
        return False

# Test ports
target = input("Enter target IP or hostname: ")
ports = [21, 22, 80, 443]

print(f"Scanning {target}...")
for port in ports:
    if scan_port(target, port):
        print(f"✅ Port {port} is OPEN")
    else:
        print(f"❌ Port {port} is CLOSED")
