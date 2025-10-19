# detect suspicious ips
import re
from collections import Counter

def analyze_auth_log(log_file="/var/log/auth.log"):                                             # 1. /var/log/auth.log This is the Linux authentication log — it stores all login attempts, sudo uses, SSH connections, etc.
	failed_ssh_pattern = re.compile(r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)')        # (\d+\.\d+\.\d+\.\d+) → matches IPv4 addresses like 203.0.113.45

	suspicious_ips = []

	try:
		with open(log_file, 'r') as f:
			for line in f:
				match = failed_ssh_pattern.search(line)
				if match:
					suspicious_ips.append(match.group(1))
	except FileNotFoundError:
		print(f"Error: {log_file} not found. Try with sudo?")
	
	# count ips and show top attackers
	ip_counts = Counter(suspicious_ips)
	print("Top Suspicious IPs (Failed SSH Logins): ")
	for ip, count in ip_counts.most_common(5):
		print(f"{ip}:{count} attempts")

if __name__ == "__main__":
	analyze_auth_log()
