import hashlib
import ssdeep
import os
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class FileMonitor(FileSystemEventHandler):
    def __init__(self):
        self.baseline = {}  # Stores original file hashes
        
    def hash_file(self, path):
        """Safe file hashing with error handling"""
        try:
            if not os.path.exists(path):
                return None, None
                
            with open(path, 'rb') as f:
                data = f.read()
                sha256 = hashlib.sha256(data).hexdigest()
                fuzzy = ssdeep.hash(data) if data else None
                return (sha256, fuzzy)
                
        except (PermissionError, IsADirectoryError) as e:
            print(f"[!] Skipping {path}: {str(e)}")
            return None, None
            
    def on_modified(self, event):
        """Handle file modifications with snap temp file filtering"""
        if event.is_directory:
            return
            
        # Skip snap temporary files and dotfiles
        if '/snap-private-tmp/' in event.src_path or event.src_path.startswith('.'):
            return
            
        current_hash, current_fuzzy = self.hash_file(event.src_path)
        
        # Only compare if we had a baseline and got valid hashes
        if None in (current_hash, current_fuzzy):
            return
            
        if event.src_path in self.baseline:
            baseline_hash, baseline_fuzzy = self.baseline[event.src_path]
            
            if current_hash != baseline_hash:
                print(f"\n[!] Alert: {event.src_path} was modified!")
                print(f"    Old hash: {baseline_hash}")
                print(f"    New hash: {current_hash}")
                
                # Fuzzy hash comparison for similarity detection
                if baseline_fuzzy and current_fuzzy:
                    similarity = ssdeep.compare(baseline_fuzzy, current_fuzzy)
                    if similarity < 80:  # Threshold for significant changes
                        print(f"    Similarity: {similarity}% (possible substantial change)")

def scan_initial_files(path):
    """Initialize baseline hashes with progress feedback"""
    baseline = {}
    total = sum(1 for _ in Path(path).rglob('*') if _.is_file())
    processed = 0
    
    for file in Path(path).rglob('*'):
        if file.is_file():
            str_path = str(file)
            if '/snap-private-tmp/' not in str_path:  # Skip snap temp files
                hashes = FileMonitor().hash_file(str_path)
                if None not in hashes:
                    baseline[str_path] = hashes
                    
            processed += 1
            if processed % 100 == 0:
                print(f"\rScanning: {processed}/{total} files processed", end='')
    
    print(f"\nInitial scan complete. Monitoring {len(baseline)} files.")
    return baseline

if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "/tmp"
    
    print(f"Starting integrity monitor for: {path}")
    monitor = FileMonitor()
    monitor.baseline = scan_initial_files(path)

    observer = Observer()
    observer.schedule(monitor, path, recursive=True)
    observer.start()

    try:
        print("Monitoring active. Press Ctrl+C to stop...")
        while True:
            pass
    except KeyboardInterrupt:
        observer.stop()
        print("\nStopping monitor...")
    observer.join()