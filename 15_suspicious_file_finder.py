import os

RISKY_EXTENSIONS = [".exe", ".bat", ".cmd", ".scr", ".js", ".vbs"]

def scan_folder(folder_path):
    print(f"\nScanning folder: {folder_path}\n")

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            #print(f"Found file: {file_path}")  # Show all files
            for ext in RISKY_EXTENSIONS:
                if file.lower().endswith(ext):
                    print(f"[!] Suspicious file: {file_path}")
                    break

if __name__ == "__main__":
    folder = input("Enter folder path: ").strip()
    if os.path.exists(folder):
        scan_folder(folder)
    else:
        print("[!] Folder does not exist.")
