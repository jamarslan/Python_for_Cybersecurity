import random
import time

# Function to generate a timestamp
def get_timestamp():
	return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
# List of fake users and tasks
users = ["SYSTEM", "Administrator", "user91", "user15"]
task_names = ["Malicious Task", "Test Task","Important Task"]
task_actions=[
	"C:\\Windows\\System32\\schtasks.exe/create /tn 'Malicious Task'/tr'cmd.exe /c echo This is a test'/sc daily",
	"C:\\Windows\\System32\\schtasks.exe/change /tn 'Malicious Task' /tr'cmd.exe /c echo Task Modified'",
	"C:\\Windows\\System32\\schtasks.exe /delete /tn 'Malicious Task'/f"
]
event_codes = [4698, 4702, 4699]
hostnames = ["Windows-Host01", "Windows-Host02", "Windows-Host03"]

# Function to generate an Event log
def generate_event_log():
	event_code = random.choice(event_codes)
	task_name = random.choice(task_names)
	user = random.choice(users)
	hostname = random.choice(hostnames)
	task_action = random.choice(task_actions)
	timestamp = get_timestamp()
	log_entry = f"{timestamp} - EventCode={event_code} - TaskName={task_name} - User={user} - Host={hostname} - TaskAction={task_action}"
	return log_entry
# Generate  logs and write to file
with open("schedule_tasks_logs.txt", "a") as f:
	for _ in range(100):
		log = generate_event_log()
		f.write(log+"\n")
