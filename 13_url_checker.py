import re 

def check_url(url):
	print(f"\n Checking URL: {url}")
	issues = []

	# 1. Check HTTPS
	if not url.lower().startswith("https://"):
		issues.append("Does not use HTTPS (secure)")

	# 2. Check for IP address instead of domain
	if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
		issues.append("Uses raw IP address instead of domain")

	# 3. Check for suspicious keywords
	suspicious_words = ["login", "varify", "update", "bank", "secure", "paypal", "free", "gift"]
	if any(word in url.lower() for word in suspicious_words):
		issues.append("Contains suspicious keywords often used in phishing.")

	# 4. Check for '@' symbol in URL
	if "@" in url:
		issues.append("'@' symbol in URL (may redirect to malicious site)")

	# 5. Check for very long URLs
	if len(url) > 75:
		issues.append("URL is unusually long")

	# 6. Check for punycode
	if "xn--" in url:
		issues.append("Contains punycode (possible IDN attach)")

	# Show result
	if issues:
		print("Potential Issues found:")
		for issue in issues:
			print(f" - {issue}")
	else:
		print("No obvious issues found.")
if __name__ == "__main__":
	test_url = input("Enter a URL to check: ")
	check_url(test_url)
