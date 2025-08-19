import socket

# Only scan common services you likely have locally
COMMON_PORTS = [22, 80, 443]  # SSH, HTTP, HTTPS

def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # IPv4 TCP socket
        sock.settimeout(5)  # Set a 5-second timeout
        sock.connect((ip, port))
        try:
            banner = sock.recv(1024).decode().strip()
            print(f"[+] Port {port} Banner: {banner}")
        except:
            print(f"[+] Port {port} is open but no banner received")
        sock.close()
    except Exception as e:
        print(f"[-] Port {port} is closed or filtered ({e})")

if __name__ == "__main__":
    ip = input("Enter target IP or hostname: ").strip()
    print(f"\nScanning {ip}...\n")
    for port in COMMON_PORTS:
        grab_banner(ip, port)
