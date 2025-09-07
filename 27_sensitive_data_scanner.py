import re
import os

SENSITIVE_PATTERNS = {
    "Credit Card Numbers": r"\b(?:\d[ -]*?){13,16}\b",  # Corrected credit card regex
    "Social Security Numbers (SSN)": r"\b\d{3}-\d{2}-\d{4}\b",  # SSN pattern
    "API Keys": r"\b[A-Za-z0-9]{32}\b",  # API key pattern
}

def scan_file(file_path):
	print(f"Scanning file: {file_path}: ")
	try:
		with open(file_path, "r") as f:
			content = f.read()
			for label, pattern in SENSITIVE_PATTERNS.items():
				matches = re.findall(pattern, content)
				if matches:
					print(f"Found {len(matches)} possible {label}!")
					for match in matches:
						print(f" - {match}")
				else:
					print(f"No {label} found.")
	except Exception as e:
		print(f"[!] Error scanning {file_path}:{e}")
def scan_directory(directory):
	print(f"\nScanning directory: {directory}\n")
	for root, dirs, files in os.walk(directory):
		for file in files:
			file_path = os.path.join(root, file)
			scan_file(file_path)
if __name__ == "__main__":
	directory = input("Enter the directory to scan: ").strip()
	if os.path.exists(directory) and os.path.isdir(directory):
		scan_directory(directory)
	else:
		print("[!] Invalid directory path.")
