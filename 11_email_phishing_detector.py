import re
def analyze_header(header_file):
	try:
		with open(header_file, "r") as f:
			headers = f.read()

		print("\n=== Email Header Analysis")

		# Detect spoofing traits
		if "SPF: fail" in headers.lower():
			print("[!] SPF check failed - sender domain could be spoofed")
		
		if "dkim=fail" in headers.lower():
			print("[!] DKIM varification failed - message integrity questionable")

		from_match = re.search(r"From:]s*(.*)", headers)
		reply_to_match = re.search(r"Reply-To:\s*(.*)", headers)

		if from_match and reply_to_match:
			from_addr = from_match.group(1).strip()
			reply_to_addr = reply_to_match(1).strip()
			if from_addr != reply_to_addr:
				print(f"[!] Mismatch: From = {from_addr}, Reply-To = {reply_to_addr}")
		if "X-PHP-Originating-Script" in headers:
			print("[!] Scripted email: Possible automated mass mailer")
		print("Header analysis complete.")

	except FileNotFoundError:
		print("Error: Email header file not found.")
	except Exception as e:
		print(f"Error: {e}")

if __name__ == "__main__":
	path = input("Enter path to email header file: ")
	analyze_header(path)
