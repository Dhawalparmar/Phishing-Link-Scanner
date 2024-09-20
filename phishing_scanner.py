import requests
from bs4 import BeautifulSoup
import re
import whois
from datetime import datetime

# Function to check if the URL is suspicious
def is_suspicious_url(url):
    suspicious_patterns = [
        r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP addresses
        r'-',  # Hyphen
        r'\.\w{2,4}\.\w{2,4}',  # Nested subdomains
        r'\d{5,}',  # Long sequences of numbers
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, url):
            return True
    return False

# WHOIS Lookup
def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if creation_date is None:
            return 0  # No creation date found
        if isinstance(creation_date, list):  
            creation_date = creation_date[0]
        domain_age = (datetime.now() - creation_date).days
        return domain_age
    except Exception as e:
        print(f"Error during WHOIS lookup: {e}")
        return None

# Check URL Content
def check_url_content(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        phishing_keywords = ['login', 'verify', 'account', 'secure', 'update', 'password']
        page_content = soup.get_text().lower()
        
        for keyword in phishing_keywords:
            if keyword in page_content:
                return True
        return False
    except Exception as e:
        print(f"Error fetching URL content: {e}")
        return False

# Main Phishing Scanner
def phishing_link_scanner(url):
    report = {}
    
    report['suspicious_structure'] = is_suspicious_url(url)
    domain = url.split('/')[2]
    domain_age = get_domain_age(domain)
    report['domain_age'] = domain_age if domain_age else "Unknown"
    
    report['content_suspicious'] = check_url_content(url)
    
    return report

# Script Entry Point
if __name__ == "__main__":
    url = input("Enter the URL to scan: ")
    report = phishing_link_scanner(url)
    
    print("\nPhishing Link Scanner Report")
    print("=" * 30)
    print(f"URL: {url}")
    print(f"Suspicious Structure: {'Yes' if report['suspicious_structure'] else 'No'}")
    print(f"Domain Age (days): {report['domain_age']}")
    print(f"Suspicious Content: {'Yes' if report['content_suspicious'] else 'No'}")
    print("=" * 30)
