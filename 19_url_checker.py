import re
import requests
from urllib.parse import urlparse

# List of blacklisted domains (for demo purposes)
BLACKLISTED_DOMAINS = [
    "example.com", "phishing-site.xyz", "malicious.com", "dangerous.org"
]

# Suspicious patterns often used in malicious URLs
SUSPICIOUS_PATTERNS = [
    r"[\?&]utm_",    # Marketing tracking parameters (could be used in phishing)
    r"@.*\.com",     # Emails hidden in URLs (could be used for phishing)
    r"\.exe$",        # Dangerous executable files in URLs
    r"%20",           # Space encoding, often used to hide malicious links
]

def check_https(url):
    """Ensure URL uses HTTPS."""
    if url.lower().startswith("https://"):
        return True
    return False

def check_blacklist(url):
    """Check if the domain is in the blacklist."""
    domain = urlparse(url).netloc
    if domain in BLACKLISTED_DOMAINS:
        return True
    return False

def check_suspicious_patterns(url):
    """Check if the URL matches any suspicious patterns."""
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, url):
            return True
    return False

def check_url_safety(url):
    """Evaluate the safety of the URL."""
    print(f"🔍 Checking URL: {url}")

    issues = []

    # Check if URL uses HTTPS
    if not check_https(url):
        issues.append("URL does not use HTTPS")

    # Check for blacklisted domains
    if check_blacklist(url):
        issues.append("URL is from a blacklisted domain")

    # Check for suspicious URL patterns
    if check_suspicious_patterns(url):
        issues.append("URL contains suspicious patterns")

    # Safety score based on the checks
    if not issues:
        print("✅ URL is safe!")
    else:
        print("⚠️  Potential Issues Detected:")
        for issue in issues:
            print(f" - {issue}")
        print("🚨 This URL is not safe!")

if __name__ == "__main__":
    print("Welcome to the Basic URL Safety Checker!\n")

    url = input("Enter a URL to check (e.g., https://example.com): ").strip()

    if not url:
        print("[!] Please enter a valid URL.")
    else:
        check_url_safety(url)
