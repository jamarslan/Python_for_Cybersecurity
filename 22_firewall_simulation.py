BLOCKED_IPS = ["192.168.0.100", "10.0.0.1"]
BLOCKED_PORTS = ["22", "80"]

def is_blocked(ip,port):
	if ip in BLOCKED_IPS:
		print(f"IP {ip} is blocked.")
		return True
	if port in BLOCKED_PORTS:
		print(f"Port {port} is blocked.")
		return True
	return False
def simulate_firewall(ip,port):
	print(f"Checking {ip} and {port}: \n")
	if is_blocked(ip,port):
		print(f"[DENIED] IP {ip} and PORT {port} are blocked.")
	else:
		print(f"[Allowed] IP {ip} and PORT {port} are not blocked.")
if __name__ == "__main__":
	test_connections = [
				("192.168.0.100", 80)
,				("192.168.0.101", 8080)
,				("192.168.0.100", 22)
				]
	for ip, port in test_connections:
		simulate_firewall(ip,port)
