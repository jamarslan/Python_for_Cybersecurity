# password checker
from getpass import getpass #hides input
common_passwords = ["password", "123456", "admin"]
correct_password = "cyber123"

attempts = 3
while attempts > 0:
	user_input = getpass("Enter password ({attemps} attempts left): ")
	if user_input in common_passwords:
		print("Too easy! Use a stronger password.")
		
	if user_input == correct_password:
		print("Access granted! ")
		break
	else:
		attempts -= 1
else:
	print("Too many failed attempts. Locking...")
