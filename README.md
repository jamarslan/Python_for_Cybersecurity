30 Python Cybersecurity Programs — Summary & Roadmap
This document summarizes 30 beginner-friendly Python programs focused on cybersecurity. Each
item includes a short description and suggested commands or notes to run and test the program
locally.
Prerequisites & Notes:
• Python 3.x (use python3)
• Create and activate a virtual environment for installing Python packages
• Common packages: scapy, python-docx, reportlab, pycryptodome (install in venv)
• Run network-related scripts with appropriate privileges (e.g., sudo) when required
Programs Summary:
1. Password Strength Checker
Checks if a password is strong using rules like length, uppercase, numbers, and special
characters.
2. Port Scanner
Scans a target IP/hostname for open ports.
3. Brute Force Simulator
Simulates brute force attacks on a simple password for learning purposes.
4. Log Analyzer
Reads log files and extracts errors/warnings for analysis (e.g., failed SSH attempts).
5. Keylogger (Educational)
Records keystrokes to a file (for local study only; do not use on others' machines).
6. Packet Sniffer
Captures and displays network packets with source/destination IPs and ports (uses Scapy).
7. PE Analyzer
Reads headers of executable files to detect anomalies (PE format analysis).
8. File Integrity Monitor
Monitors file changes using hashing (SHA256) to detect tampering.
9. Traffic Analyzer
Captures and analyzes live network traffic and artifacts like ARP spoofing signs.
10. SSH Defender
Detects failed SSH login attempts from logs and summarizes suspicious IPs.
11. Email Phishing Detector
Parses raw email headers and flags suspicious traits (SPF/DKIM failures, mismatched Reply-To).
12. Malware Hash Checker
Computes file hashes (SHA256) and checks VirusTotal (or local DB) for detections.
13. Directory Brute-forcer
Tries common directory names on a web server to discover hidden pages (safe for local/owned
targets).
14. Suspicious File Finder
Scans folders for files with risky extensions (e.g., .exe, .bat) and double-extensions.
15. Simple Antivirus (Hash-Based)
Scans files for known malicious hashes from a local signature list.
16. Word to PDF Converter
Converts .docx files to .pdf using python-docx and reportlab (basic formatting).17. SSH Log Monitor
Monitors auth logs for failed SSH logins and alerts in real time.
18. Enhanced Password Leak & Strength Checker
Checks if a password appears in a local leaked list and scores strength with suggestions.
19. Basic URL Safety Checker
Evaluates a URL for HTTPS, blacklists, and suspicious patterns (regex checks).
20. Port Banner Grabber
Connects to open ports and grabs service banners to identify running services.
21. File Permissions Checker
Scans directories and flags files with insecure permissions (e.g., 777, 666).
22. Basic Firewall Simulator
Simulates firewall rules by blocking IPs or ports based on simple checks.
23. File Encryptor/Decryptor
Encrypts and decrypts files using AES (symmetric crypto) with basic padding (learning use).
24. Sensitive Data Scanner
Scans files for potential sensitive data (credit cards, SSNs, API keys) using regex patterns.
25. Key Management System (KMS) Demo
Generates, stores, and retrieves AES keys in a simple JSON-based vault (simulation).
26. Malware Filename Scanner
Flags suspicious filenames and extensions commonly associated with malware.
27. Local Packet Logger
Logs local packets with IP, protocol, and size for later review (uses Scapy).
28. ARP Spoof Detector
Monitors ARP replies and alerts if the gateway MAC changes (possible spoofing).
29. Wi-Fi Scanner (nmcli)
Lists nearby Wi-Fi SSIDs, signal strength, and security type using nmcli on Linux.
30. Local IDS Simulator
Combines ARP spoof detection and packet logging to simulate an intrusion detection system
(IDS).
How to proceed
Follow the programs in order to build foundational skills. For network tasks, prefer testing on
localhost or controlled VMs. Keep any keys and sensitive test data private and do not run
potentially invasive scripts on systems you do not own. Good luck with your learning — you now
have a complete 30-program roadmap!
