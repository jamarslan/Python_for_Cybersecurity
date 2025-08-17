import re
LEAKED_PASSWORD = ["123456", "password", "qwerty", "abc123","letmain", "welcome", "admin", "iloveyou"]

def check_leak(password):
	if password in LEAKED_PASSWORD:
		return True
	return False
def password_strength(password):
	score = 0
	suggestions = []
	if len(password) >= 8:
		score += 1
	else:
		suggestions.append("Use at least 8 characters")
	if re.search(r'[A-Z]', password):
		score += 1
	else:
		suggestions.append("Use Uppercase letters")
	if re.search(r'[a-z]', password):
		score += 1
	else:
		suggestions.append("Use Lowercase letters")	
	if re.search(r'[0-9]', password):
		score += 1
	else:
		suggestions.append("Use Digits")
	if re.search(r'[\W_]', password):
		score += 1
	else:
		suggestions.append("Use Special Characters")
	if score == 5:
		strength = "Strong"
	elif score >= 3:
		strength = "Medium"
	else:
		strength = "Weak"
	return strength, suggestions

def check_password(password):
	print(f"\nChecking password: '{password}'")
	if check_leak(password):
		print("ALERT: This password has been leaked before!")
	else:
		print("Safe: Not found in leaked passwords list")
	
	strength, suggestions = password_strength(password)
	print(f"Password Strength: {strength}")
	if suggestions:
		print("Suggestions to improve: ")
		for s in suggestions:
			print(f" - {s}")

if __name__ == "__main__":
	print("Welcome to the Password Leak and Strength Checker!")
	print("You can check multiple passwords separated by commas.\n")
	input_passwords = input("Enter password(s) to check: ").strip()
	passwords = [p.strip() for p in input_passwords.split(",") if p.strip()]

	if not passwords:
		print["[!] No passwords entered. Exiting."]
	else:
		for pwd in passwords:
			check_password(pwd)
