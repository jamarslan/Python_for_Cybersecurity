# brute force simulation

import time

# Mock credentials

real_username = "admin"
real_password = "secure123"

def login(username, password):
	time.sleep(0.5)
	return username == real_username and password == real_password

wordlist = ["admin", "passsword", "123456", "secure123", "letmeain"]

def brute_force():
	attempts = 0
	for password in wordlist:
		if  attempts >  2:
			print("Account locked due to too many attempts!")
			exit()
		attempts = attempts + 1

		print(f"Trying: {password}")
		if login("admin", password):
			print(f"Success! Password is '{password}'")
			return
	print("Failed to crack password")
brute_force()
