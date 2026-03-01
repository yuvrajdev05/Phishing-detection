import re
import socket
from urllib.parse import urlparse
import tldextract
import whois
from datetime import datetime

class URLFeatureExtractor:
    def __init__(self):
        self.homoglyphs = {
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y',
            'і': 'i', 'ј': 'j', 'л': 'l', 'н': 'n', 'т': 't', 'х': 'x'
        }

    def extract_features(self, url, skip_whois=False):
        parsed_url = urlparse(url)
        extracted = tldextract.extract(url)
        
        domain = extracted.domain + "." + extracted.suffix
        subdomain = extracted.subdomain
        
        features = {}
        
        # 1. URL Content Features
        features['url_length'] = len(url)
        features['subdomain_count'] = len(subdomain.split('.')) if subdomain else 0
        features['has_https'] = 1 if parsed_url.scheme == 'https' else 0
        
        # 2. Special Characters Check
        special_chars = ['@', '?', '-', '=', '_', '.', '%']
        for char in special_chars:
            features[f'count_{char}'] = url.count(char)
            
        # 3. IP-based URL
        features['is_ip_address'] = 1 if self._is_ip(extracted.domain) else 0
        
        # 4. Homoglyph Detection
        features['has_homoglyph'] = 1 if self._check_homoglyph(url) else 0
        
        # 5. Domain Age
        features['domain_age_days'] = self._get_domain_age(domain) if not skip_whois else 365
        
        # Additional features for robustness
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_params'] = len(parsed_url.query.split('&')) if parsed_url.query else 0
        
        return features

    def _is_ip(self, domain):
        try:
            socket.inet_aton(domain)
            return True
        except:
            return False

    def _check_homoglyph(self, url):
        for char in url:
            if char in self.homoglyphs:
                return True
        return False

    def _get_domain_age(self, domain):
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age = (datetime.now() - creation_date).days
                return max(0, age)
        except:
            pass
        return 0 # Default if lookup fails

extractor = URLFeatureExtractor()
