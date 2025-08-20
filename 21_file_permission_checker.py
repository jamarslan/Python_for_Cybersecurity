import os
RISKY_PERMISSIONS = ["777","666"]
def check_permissions(file_path):
	permissions = oct(os.stat(file_path).st_mode)[-3:]
	if permissions in RISKY_PERMISSIONS:
		return True
	return False
def scan_directory(directory):
	print(f"Scanning directory: {directory}")
	risky_files = 0
	for root, dirs, files in os.walk(directory):
		for file in files:
			file_path = os.path.join(root, file)
			if check_permissions(file_path):
				risky_files += 1
	if risky_files == 0:
		print("No risky permission found.")
	print(f"\n {risky_files} risky file(s) found with dangerous permissions.")
if __name__ == "__main__":
	directory = input("Enter the directory path to scan: ").strip()
	if os.path.exists(directory) and os.path.isdir(directory):
		scan_directory(directory)
	else:
		print("[!] Invalid directory path.")
