import urllib.parse
import re
import socket
import ssl
import requests
import whois
from datetime import datetime

# Common URL shorteners
SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'rebrand.ly', 'ouo.io', 
    'goo.gl', 'bit.do', 'adf.ly', 'tiny.cc', 'ow.ly', 't2mio.com', 'shorte.st',
    'lnkd.in', 'db.tt', 'qr.ae', 'git.io', 'linktr.ee', 'trib.al', 'bitly.com'
}

# Suspicious keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'update', 'signin', 'bank', 
    'webscr', 'cmd', 'ebayisapi', 'paypal', 'banking', 'confirm', 
    'wp-admin', 'wp-content', 'submit', 'recover', 'bonus', 'wallet',
    'password', 'credential', 'support', 'service', 'free', 'giftcard'
]

# Common two-part TLD suffixes
DOUBLE_TLDS = {
    'co.uk', 'me.uk', 'org.uk', 'net.uk', 'co.jp', 'co.nz', 'com.au', 
    'net.au', 'org.au', 'com.br', 'co.in', 'net.in', 'org.in', 'com.sg', 
    'com.my', 'com.hk'
}

def normalize_url(url):
    """Normalize the URL by stripping spaces and prepending protocol if missing."""
    url = url.strip()
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'http://' + url
    return url

def check_ip_address(hostname):
    """Check if the hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return 0
    # IPv4 check
    try:
        socket.inet_aton(hostname)
        return 1
    except socket.error:
        pass
    # IPv6 check
    try:
        socket.inet_pton(socket.AF_INET6, hostname)
        return 1
    except socket.error:
        pass
    return 0

def count_subdomains(hostname):
    """Calculate the number of subdomains in the hostname."""
    if not hostname or check_ip_address(hostname):
        return 0
    
    parts = hostname.split('.')
    if len(parts) <= 2:
        return 0
        
    # Handle two-part TLDs (e.g. co.uk)
    suffix = '.'.join(parts[-2:])
    if suffix in DOUBLE_TLDS:
        return max(0, len(parts) - 3)
        
    return max(0, len(parts) - 2)

def check_shortened(hostname):
    """Check if the hostname is a known URL shortening service."""
    if not hostname:
        return 0
    host = hostname.lower()
    if host.startswith('www.'):
        host = host[4:]
    if host in SHORTENERS:
        return 1
    for s in SHORTENERS:
        if host.endswith('.' + s):
            return 1
    return 0

def count_keywords(url):
    """Count the occurrences of suspicious keywords in the entire URL."""
    url_lower = url.lower()
    return sum(url_lower.count(kw) for kw in SUSPICIOUS_KEYWORDS)

def check_ssl(url, timeout=2):
    """Check if the HTTPS certificate is valid."""
    if not url.lower().startswith('https://'):
        return 0
    try:
        # Use HEAD request for speed, verify=True will raise SSLError if invalid
        requests.head(url, verify=True, timeout=timeout, allow_redirects=True)
        return 1
    except requests.exceptions.SSLError:
        return 0
    except Exception:
        # Fallback manual SSL handshake if site is slow/blocker on HEAD
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return 0
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssock.getpeercert()
            return 1
        except Exception:
            return 0

def get_redirects(url, timeout=2):
    """Count the number of redirects."""
    try:
        response = requests.head(url, allow_redirects=True, timeout=timeout)
        return len(response.history)
    except Exception:
        return 0

def get_domain_age(hostname, timeout=2):
    """Fetch the domain age in days from WHOIS database."""
    if not hostname or check_ip_address(hostname):
        return -1
    
    parts = hostname.split('.')
    if len(parts) <= 1:
        return -1
    
    # Resolve root registerable domain
    if len(parts) > 2:
        suffix = '.'.join(parts[-2:])
        if suffix in DOUBLE_TLDS:
            domain = '.'.join(parts[-3:])
        else:
            domain = '.'.join(parts[-2:])
    else:
        domain = hostname

    try:
        # Query WHOIS registry
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        if not creation_date:
            return -1
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if not isinstance(creation_date, datetime):
            return -1
            
        age = (datetime.now() - creation_date).days
        return age
    except Exception:
        return -1

def extract_features(url, offline=False):
    """
    Extract a dictionary of features from a raw URL.
    If offline is True, live network features (SSL validity, redirects, WHOIS lookup)
    will be populated with neutral/default values to prevent training delays or IP blocking.
    """
    normalized = normalize_url(url)
    parsed = urllib.parse.urlparse(normalized)
    hostname = parsed.hostname or ''
    path = parsed.path or ''
    
    # Lexical features
    url_length = len(normalized)
    num_dots = normalized.count('.')
    has_at = 1 if '@' in normalized else 0
    has_dash = 1 if '-' in normalized else 0
    
    # '//' in path (excluding the one in http:// or https://)
    has_double_slash_path = 1 if '//' in path else 0
    
    use_ip = check_ip_address(hostname)
    num_subdomains = count_subdomains(hostname)
    num_suspicious_keywords = count_keywords(normalized)
    is_shortened = check_shortened(hostname)
    is_https = 1 if normalized.startswith('https://') else 0
    
    # Network/live features
    if offline:
        ssl_valid = 0
        domain_age_days = -1
        num_redirects = 0
    else:
        ssl_valid = check_ssl(normalized)
        domain_age_days = get_domain_age(hostname)
        num_redirects = get_redirects(normalized)
        
    return {
        'url_length': url_length,
        'num_dots': num_dots,
        'has_at': has_at,
        'has_dash': has_dash,
        'has_double_slash_path': has_double_slash_path,
        'use_ip': use_ip,
        'num_subdomains': num_subdomains,
        'num_suspicious_keywords': num_suspicious_keywords,
        'is_shortened': is_shortened,
        'is_https': is_https,
        'ssl_valid': ssl_valid,
        'domain_age_days': domain_age_days,
        'num_redirects': num_redirects
    }
