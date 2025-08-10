# hash generator
import hashlib

def hash_generator(file_path):
	try:
		with open(file_path, "rb") as f:
			file_data = f.read()
		
		md5_hash = hashlib.md5(file_data).hexdigest()
		sha1_hash = hashlib.sha1(file_data).hexdigest()
		sha256_hash = hashlib.sha256(file_data).hexdigest()

		print(f"\nFile: {file_path}")
		print(f"MD5: {md5_hash}")
		print(f"SHA1: {sha1_hash}")
		print(f"SHA256: {sha256_hash}")
	except FileNotFoundError:
		print(f"[!] File not found.")
	except PermissionError:
		print(f"[!] Permission denied.")
	except Exception as e:
		print(f"[!] Error:{e}")
if __name__ == "__main__":
	file_path = input("Enter file path: ")
	hash_generator(file_path)
