import os
import subprocess
import ipaddress
def ping_ip(ip):
	try:
		result = subprocess.run(['ping', '-c', '1', str(ip)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		if result.returncode == 0:
			return True
		else:
			return False
	except Exception as e:
		print(f"[!] Error while pinging {ip}:{e}")
		return False
		
def scan_range(network):
	print(f"\nScanning range: {network}")
	active_ips = []
	for ip in ipaddress.IPv4Network(network).hosts():
		print(f"Pinging {ip}")
		if ping_ip(ip):
			print(f"{ip} is online")
			active_ips.append(str(ip))
		else:
			print(f"{ip} is offline")
	if active_ips:
		print(f"\nActive IPs found: {', '.join(active_ips)}")
	else:
		print("No active IPs found.")
		
if __name__ == "__main__":
	network = input("Enter the IP range to scan (e.g., 192.168.1.0/24): ")
	try:
		ipaddress.IPv4Network(network)
		scan_range(network)
	except ValueError:
		print("[!] Invalid IP range. Please provide a valid CIDR notation")
