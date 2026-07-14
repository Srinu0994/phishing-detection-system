import os
import sys
import unittest
import json

# Ensure the backend directory is in the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from feature_extraction import (
    normalize_url, 
    check_ip_address, 
    count_subdomains, 
    check_shortened, 
    count_keywords, 
    extract_features
)

class TestFeatureExtraction(unittest.TestCase):
    def test_normalize_url(self):
        self.assertEqual(normalize_url("google.com"), "http://google.com")
        self.assertEqual(normalize_url("https://google.com"), "https://google.com")
        self.assertEqual(normalize_url("  http://google.com  "), "http://google.com")

    def test_check_ip_address(self):
        self.assertEqual(check_ip_address("192.168.1.1"), 1)
        self.assertEqual(check_ip_address("google.com"), 0)
        # IPv6
        self.assertEqual(check_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), 1)

    def test_count_subdomains(self):
        self.assertEqual(count_subdomains("google.com"), 0)
        self.assertEqual(count_subdomains("www.google.com"), 1)
        self.assertEqual(count_subdomains("sub.www.google.com"), 2)
        # Two-part TLD test
        self.assertEqual(count_subdomains("google.co.uk"), 0)
        self.assertEqual(count_subdomains("sub.google.co.uk"), 1)

    def test_check_shortened(self):
        self.assertEqual(check_shortened("bit.ly"), 1)
        self.assertEqual(check_shortened("www.tinyurl.com"), 1)
        self.assertEqual(check_shortened("google.com"), 0)

    def test_count_keywords(self):
        self.assertEqual(count_keywords("http://google.com/login-verify-account"), 3)
        self.assertEqual(count_keywords("http://google.com"), 0)

    def test_extract_features_offline(self):
        feats = extract_features("http://login-verify.bit.ly/update", offline=True)
        self.assertEqual(feats['url_length'], len("http://login-verify.bit.ly/update"))
        self.assertEqual(feats['is_shortened'], 1)
        self.assertEqual(feats['num_suspicious_keywords'], 3)
        self.assertEqual(feats['ssl_valid'], 0) # offline default
        self.assertEqual(feats['domain_age_days'], -1) # offline default
        self.assertEqual(feats['num_redirects'], 0) # offline default

if __name__ == "__main__":
    unittest.main()
