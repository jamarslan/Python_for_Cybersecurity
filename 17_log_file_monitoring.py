# log file monitoring for suspicious patterns
import time

SUSPICIOUS_PATTERNS = ["Failed password", "unathorized","ssh", "invalid user"]

def log_file_monitoring(log_file, interval = 5):
	print(f"Monitoring log file {log_file} for suspicious patterns...\n")
	try:
		with open(log_file, "r") as f:
			f.seek(0,2)
			while True:
				line = f.readline()
				if line:
					for pattern in 	SUSPICIOUS_PATTERNS:
						if pattern in line:
							print(f"[ALERT] Found suspicious pattern: {pattern}")
							print(f"log entry: {line.strip()}")
						else:
							time.sleep(interval)
	except FileNotFoundError:
		print(f"Error: The file {log_file} does not exists.")
	except PermissionError:
		print(f"Error: YOu do not have permission to read {log_file}. Try running with sudo permissions")
	except Exception as e:
		print(f"Error occurred {e}")

if __name__ == "__main__":
	file = input("Enter log file (e.g., /var/log/auth.log): ").strip()
	log_file_monitoring(file)
					
