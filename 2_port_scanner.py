# port scanner

import socket

ports = [21,22,80,443]
target = input("Enter target IP or hostname: ")
def scan_port(ip, port):
	try:
		sock = socket.socket(socket.AFT_INET, socket.SOCK_STREAM)
		sock.settimeout(1) # Timeout to avoid time handing
		result = sock.connectex(ip, port)
		sock.close()
		return result == 0
	except:
		return False

print(f"Scanning {target}...")
for port in ports:
	if scan_port(target, port):
		print("Port {port} is OPEN")
	else:
		print(f"Port {port} is CLOSED")
