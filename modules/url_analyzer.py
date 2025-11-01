"""
URL-Based Phishing Detection Module for PhishFusion-Net
========================================================

This module implements URL-based features for phishing detection including:
- Lexical analysis (URL length, special characters, entropy)
- Domain age and registration analysis
- SSL/HTTPS validation
- Suspicious pattern detection (homograph attacks, IP addresses)
- Brand impersonation detection
- Redirect chain analysis

Author: PhishFusion-Net Team
Date: November 2025
"""

import re
import socket
import ssl
import urllib.parse
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, List
import tldextract
import requests
from urllib.parse import urlparse
import math
from collections import Counter
import ipaddress
import warnings

# Suppress SSL and urllib3 warnings for phishing site analysis
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
warnings.filterwarnings('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class URLAnalyzer:
    """
    Comprehensive URL analysis for phishing detection
    """
    
    def __init__(self, timeout=5):
        """
        Initialize URL Analyzer
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free domains
            '.xyz', '.top', '.work', '.click', '.link',  # Suspicious TLDs
            '.loan', '.racing', '.download', '.stream'
        ]
        
        # Homograph attack characters (lookalike characters)
        self.homograph_map = {
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',  # Cyrillic
            'х': 'x', 'у': 'y', 'і': 'i',
            'ı': 'i', 'ο': 'o', 'ν': 'v',  # Greek
        }
        
        # Common brand keywords for impersonation detection
        self.brand_keywords = [
            'paypal', 'amazon', 'google', 'microsoft', 'apple',
            'facebook', 'instagram', 'netflix', 'bank', 'secure',
            'login', 'signin', 'verify', 'account', 'update',
            'confirm', 'suspended', 'locked', 'alert'
        ]

    def analyze(self, url: str) -> Dict:
        """
        Perform comprehensive URL analysis
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary containing all URL features and risk scores
        """
        features = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
        }
        
        try:
            # Lexical features
            features.update(self._extract_lexical_features(url))
            
            # Domain features
            features.update(self._extract_domain_features(url))
            
            # SSL/HTTPS features
            features.update(self._check_ssl_certificate(url))
            
            # Suspicious pattern detection
            features.update(self._detect_suspicious_patterns(url))
            
            # Redirect analysis
            features.update(self._analyze_redirects(url))
            
            # Calculate overall risk score
            features['risk_score'] = self._calculate_risk_score(features)
            features['risk_level'] = self._categorize_risk(features['risk_score'])
            
        except Exception as e:
            features['error'] = str(e)
            features['risk_score'] = 0.5  # Neutral score on error
            features['risk_level'] = 'unknown'
        
        return features

    def _extract_lexical_features(self, url: str) -> Dict:
        """
        Extract lexical features from URL
        """
        features = {}
        
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc
            path = parsed.path
            query = parsed.query
            
            # Basic length features
            features['url_length'] = len(url)
            features['hostname_length'] = len(hostname)
            features['path_length'] = len(path)
            features['query_length'] = len(query)
            
            # Character count features
            features['dot_count'] = url.count('.')
            features['dash_count'] = url.count('-')
            features['underscore_count'] = url.count('_')
            features['slash_count'] = url.count('/')
            features['question_count'] = url.count('?')
            features['equal_count'] = url.count('=')
            features['at_count'] = url.count('@')
            features['ampersand_count'] = url.count('&')
            features['digit_count'] = sum(c.isdigit() for c in url)
            features['letter_count'] = sum(c.isalpha() for c in url)
            
            # Ratio features
            features['digit_ratio'] = features['digit_count'] / max(len(url), 1)
            features['letter_ratio'] = features['letter_count'] / max(len(url), 1)
            
            # Entropy (measure of randomness)
            features['url_entropy'] = self._calculate_entropy(url)
            features['hostname_entropy'] = self._calculate_entropy(hostname)
            
            # Subdomain analysis
            ext = tldextract.extract(url)
            subdomain = ext.subdomain
            features['subdomain'] = subdomain
            features['subdomain_count'] = len(subdomain.split('.')) if subdomain else 0
            features['has_www'] = subdomain.startswith('www')
            
            # Port number
            features['has_port'] = ':' in hostname and hostname.split(':')[-1].isdigit()
            if features['has_port']:
                features['port_number'] = int(hostname.split(':')[-1])
            else:
                features['port_number'] = None
                
            # Suspicious length thresholds
            features['suspicious_length'] = features['url_length'] > 75
            features['very_long_url'] = features['url_length'] > 100
            
        except Exception as e:
            features['lexical_error'] = str(e)
        
        return features

    def _extract_domain_features(self, url: str) -> Dict:
        """
        Extract domain-related features
        """
        features = {}
        
        try:
            ext = tldextract.extract(url)
            domain = ext.domain
            suffix = ext.suffix
            
            features['domain'] = domain
            features['tld'] = suffix
            features['registered_domain'] = ext.registered_domain
            
            # Domain length
            features['domain_length'] = len(domain)
            
            # TLD checks
            features['is_suspicious_tld'] = ('.' + suffix) in self.suspicious_tlds
            features['is_country_tld'] = len(suffix) == 2  # Country codes are 2 chars
            
            # Check if domain is an IP address
            features['is_ip_address'] = self._is_ip_address(ext.domain)
            
            # Domain token analysis
            features['domain_tokens'] = len(domain.split('-'))
            features['domain_has_digits'] = any(c.isdigit() for c in domain)
            
            # Check for punycode (internationalized domain)
            features['is_punycode'] = domain.startswith('xn--')
            
        except Exception as e:
            features['domain_error'] = str(e)
        
        return features

    def _check_ssl_certificate(self, url: str) -> Dict:
        """
        Check SSL certificate validity
        """
        features = {
            'uses_https': False,
            'valid_ssl': False,
            'ssl_issuer': None,
            'ssl_expires': None,
            'ssl_age_days': None
        }
        
        try:
            parsed = urlparse(url)
            features['uses_https'] = parsed.scheme == 'https'
            
            if not features['uses_https']:
                return features
            
            hostname = parsed.hostname
            if not hostname:
                return features
            
            # Get SSL certificate
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    features['valid_ssl'] = True
                    features['ssl_issuer'] = dict(x[0] for x in cert['issuer'])
                    
                    # Parse expiration date
                    not_after = cert['notAfter']
                    expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    features['ssl_expires'] = expire_date.isoformat()
                    
                    # Calculate certificate age
                    not_before = cert['notBefore']
                    issue_date = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                    features['ssl_age_days'] = (datetime.now() - issue_date).days
                    
                    # Check if certificate is about to expire
                    days_until_expire = (expire_date - datetime.now()).days
                    features['ssl_expires_soon'] = days_until_expire < 30
                    features['ssl_is_expired'] = days_until_expire < 0
                    
        except ssl.SSLError as e:
            features['ssl_error'] = 'SSL Error: ' + str(e)
            features['valid_ssl'] = False
        except socket.timeout:
            features['ssl_error'] = 'Timeout'
        except Exception as e:
            features['ssl_error'] = str(e)
        
        return features

    def _detect_suspicious_patterns(self, url: str) -> Dict:
        """
        Detect suspicious patterns in URL
        """
        features = {}
        
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc.lower()
            path = parsed.path.lower()
            full_url = url.lower()
            
            # Check for @ symbol (can hide real domain)
            features['has_at_symbol'] = '@' in hostname
            
            # Check for double slash in path (suspicious redirects)
            features['has_double_slash'] = '//' in path
            
            # Check for IP address instead of domain
            features['uses_ip_address'] = self._is_ip_address(hostname.split(':')[0])
            
            # Homograph attack detection
            features['has_homograph'] = self._detect_homograph(hostname)
            
            # Brand impersonation detection
            features['brand_impersonation'] = self._detect_brand_impersonation(full_url)
            
            # URL shortener detection
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
            features['is_shortened'] = any(s in hostname for s in shorteners)
            
            # Check for misleading TLD
            features['tld_in_path'] = any(
                tld in path for tld in ['.com', '.net', '.org']
            )
            
            # Suspicious keyword detection
            suspicious_keywords = [
                'verify', 'account', 'update', 'confirm', 'secure',
                'banking', 'suspended', 'locked', 'unusual', 'click'
            ]
            features['suspicious_keyword_count'] = sum(
                1 for keyword in suspicious_keywords if keyword in full_url
            )
            
            # Check for excessive subdomains (subdomain squatting)
            ext = tldextract.extract(url)
            subdomain_parts = ext.subdomain.split('.') if ext.subdomain else []
            features['excessive_subdomains'] = len(subdomain_parts) > 3
            
        except Exception as e:
            features['pattern_error'] = str(e)
        
        return features

    def _analyze_redirects(self, url: str) -> Dict:
        """
        Analyze redirect chains
        """
        features = {
            'redirect_count': 0,
            'final_url': url,
            'has_redirects': False,
            'redirect_chain': []
        }
        
        try:
            response = requests.head(
                url,
                allow_redirects=True,
                timeout=self.timeout,
                verify=False
            )
            
            # Check redirect history
            if response.history:
                features['has_redirects'] = True
                features['redirect_count'] = len(response.history)
                features['final_url'] = response.url
                features['redirect_chain'] = [r.url for r in response.history]
                
                # Check if redirect changes domain
                original_domain = tldextract.extract(url).registered_domain
                final_domain = tldextract.extract(response.url).registered_domain
                features['redirect_changes_domain'] = (original_domain != final_domain)
                
        except requests.exceptions.SSLError:
            features['redirect_error'] = 'SSL Error'
        except requests.exceptions.Timeout:
            features['redirect_error'] = 'Timeout'
        except Exception as e:
            features['redirect_error'] = str(e)
        
        return features

    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of text
        """
        if not text:
            return 0.0
        
        counts = Counter(text)
        length = len(text)
        
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy

    def _is_ip_address(self, text: str) -> bool:
        """
        Check if text is an IP address
        """
        try:
            ipaddress.ip_address(text)
            return True
        except ValueError:
            return False

    def _detect_homograph(self, text: str) -> bool:
        """
        Detect homograph attack (lookalike characters)
        """
        for char in text:
            if char in self.homograph_map:
                return True
        return False

    def _detect_brand_impersonation(self, url: str) -> Optional[str]:
        """
        Detect brand impersonation attempts
        """
        url_lower = url.lower()
        
        for brand in self.brand_keywords:
            if brand in url_lower:
                # Check if it's legitimate or impersonation
                ext = tldextract.extract(url)
                domain = ext.domain.lower()
                
                # If brand is in domain but with modifications, it's suspicious
                if brand in domain and brand != domain:
                    return brand
                
                # If brand is in subdomain or path (not main domain)
                if brand in ext.subdomain.lower() or brand in urlparse(url).path.lower():
                    return brand
        
        return None

    def _calculate_risk_score(self, features: Dict) -> float:
        """
        Calculate overall risk score (0-1, higher is more suspicious)
        """
        score = 0.0
        weight_sum = 0.0
        
        # Weight different features
        checks = [
            ('is_ip_address', 0.15),
            ('has_at_symbol', 0.10),
            ('has_homograph', 0.15),
            ('brand_impersonation', 0.12),
            ('is_suspicious_tld', 0.08),
            ('suspicious_length', 0.05),
            ('very_long_url', 0.08),
            ('excessive_subdomains', 0.07),
            ('has_double_slash', 0.05),
            ('tld_in_path', 0.06),
            ('ssl_is_expired', 0.10),
            ('redirect_changes_domain', 0.08),
            ('is_shortened', 0.04),
        ]
        
        for feature, weight in checks:
            if feature in features:
                weight_sum += weight
                if features[feature]:
                    score += weight
        
        # HTTPS check (negative weight - good sign)
        if features.get('uses_https') and features.get('valid_ssl'):
            score -= 0.10
            weight_sum += 0.10
        elif not features.get('uses_https'):
            score += 0.08
            weight_sum += 0.08
        
        # Entropy-based checks
        if features.get('url_entropy', 0) > 4.5:
            score += 0.05
            weight_sum += 0.05
        
        # Suspicious keyword count
        keyword_count = features.get('suspicious_keyword_count', 0)
        if keyword_count > 0:
            score += min(keyword_count * 0.03, 0.10)
            weight_sum += 0.10
        
        # Normalize score
        if weight_sum > 0:
            score = score / weight_sum
        
        return min(max(score, 0.0), 1.0)

    def _categorize_risk(self, score: float) -> str:
        """
        Categorize risk level based on score
        """
        if score >= 0.7:
            return 'high'
        elif score >= 0.5:
            return 'medium'
        elif score >= 0.3:
            return 'low'
        else:
            return 'safe'

    def get_summary(self, features: Dict) -> str:
        """
        Generate human-readable summary of analysis
        """
        risk_score = features.get('risk_score', 0)
        risk_level = features.get('risk_level', 'unknown')
        
        summary = f"URL Risk Analysis Summary:\n"
        summary += f"Risk Score: {risk_score:.2f} ({risk_level.upper()})\n\n"
        
        summary += "Suspicious Indicators:\n"
        
        if features.get('is_ip_address'):
            summary += "  ⚠ URL uses IP address instead of domain name\n"
        if features.get('has_at_symbol'):
            summary += "  ⚠ URL contains @ symbol (can hide real domain)\n"
        if features.get('has_homograph'):
            summary += "  ⚠ URL contains lookalike characters (homograph attack)\n"
        if features.get('brand_impersonation'):
            summary += f"  ⚠ Possible brand impersonation: {features['brand_impersonation']}\n"
        if features.get('is_suspicious_tld'):
            summary += f"  ⚠ Suspicious TLD: {features.get('tld')}\n"
        if features.get('very_long_url'):
            summary += f"  ⚠ Very long URL ({features.get('url_length')} characters)\n"
        if not features.get('uses_https'):
            summary += "  ⚠ No HTTPS encryption\n"
        elif not features.get('valid_ssl'):
            summary += "  ⚠ Invalid or expired SSL certificate\n"
        if features.get('redirect_changes_domain'):
            summary += "  ⚠ Redirect changes domain\n"
        
        if risk_level == 'safe':
            summary += "  ✓ No major suspicious indicators found\n"
        
        return summary


def quick_url_check(url: str) -> Tuple[float, str]:
    """
    Quick URL check - returns risk score and level
    
    Args:
        url: URL to check
        
    Returns:
        Tuple of (risk_score, risk_level)
    """
    analyzer = URLAnalyzer(timeout=3)
    features = analyzer.analyze(url)
    return features['risk_score'], features['risk_level']


if __name__ == '__main__':
    # Test the analyzer
    test_urls = [
        'https://www.google.com',
        'http://192.168.1.1/login',
        'https://paypal-secure-login-verify.tk/account',
        'https://www.paypal.com',
    ]
    
    analyzer = URLAnalyzer()
    
    for url in test_urls:
        print(f"\n{'='*60}")
        print(f"Analyzing: {url}")
        print('='*60)
        
        features = analyzer.analyze(url)
        print(analyzer.get_summary(features))
