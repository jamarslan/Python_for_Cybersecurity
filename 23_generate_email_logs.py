import random
import time
 
subjects = ["urgent", "important account update", "your account has been compromised", "varify your account"]
sender_domains = ["@fakeemail.com", "@spammail.xyz", "@phishingsite.ru"]
body_keywords = ["click here", "reset password", "varify now", "urgent action required"]

# Generate random email logs

for _ in range(100):
	subject = random.choice(subjects)
	sender = f"user{random.randint(1,100)}{random.choice(sender_domains)}"
	body = random.choice(body_keywords)
	timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
	
	log_entry = f"{timestamp} - From:{sender} - Subject:{subject} - Body:{body}\n"
	with open("email_logs.txt", "a") as f:
		f.write(log_entry)
