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
import unicodedata

# Suppress SSL and urllib3 warnings for phishing site analysis
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class URLAnalyzer:
    """
    Comprehensive URL analysis for phishing detection
    Enhanced version with fixes for production use
    """
    
    def __init__(self, timeout=5, enable_whois=False, enable_dnssec=False):
        """
        Initialize URL Analyzer
        
        Args:
            timeout: Request timeout in seconds
            enable_whois: Enable WHOIS domain age checking (slower)
            enable_dnssec: Enable DNSSEC validation (requires dnspython)
        """
        self.timeout = timeout
        self.enable_whois = enable_whois
        self.enable_dnssec = enable_dnssec
        
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
        # Extended list with more brands and variations
        self.brand_keywords = [
            # Payment services
            'paypal', 'stripe', 'square', 'venmo', 'cashapp',
            # E-commerce
            'amazon', 'ebay', 'alibaba', 'etsy', 'shopify',
            # Tech giants
            'google', 'microsoft', 'apple', 'meta', 'facebook',
            'instagram', 'twitter', 'linkedin', 'youtube',
            # Streaming/Entertainment
            'netflix', 'spotify', 'hulu', 'disney', 'twitch',
            # Banking/Finance
            'bank', 'banking', 'wellsfargo', 'chase', 'citibank',
            'payoneer', 'wise', 'revolut',
            # Security/Account keywords
            'secure', 'security', 'login', 'signin', 'verify',
            'account', 'update', 'confirm', 'suspended', 'locked',
            'alert', 'warning', 'urgent', 'action', 'required',
            # Crypto
            'coinbase', 'binance', 'crypto', 'wallet', 'blockchain'
        ]
        
        # Legitimate domains that shouldn't trigger impersonation warnings
        self.whitelisted_domains = {
            'google': ['google.com', 'youtube.com', 'gmail.com', 'gstatic.com'],
            'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'msn.com'],
            'apple': ['apple.com', 'icloud.com', 'me.com'],
            'amazon': ['amazon.com', 'amazonaws.com', 'cloudfront.net'],
            'facebook': ['facebook.com', 'fb.com', 'fbcdn.net'],
            'paypal': ['paypal.com', 'paypal-communication.com'],
            'netflix': ['netflix.com', 'nflxext.com', 'nflximg.net'],
            # Add more as needed
        }

    def analyze(self, url: str) -> Dict:
        """
        Perform comprehensive URL analysis
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary containing all URL features and risk scores
        """
        import time
        start_time = time.time()
        
        features = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'analysis_version': '2.0',  # Track version for future improvements
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
            
            # Typosquatting detection (after domain features are extracted)
            if features.get('domain'):
                typosquat = self._detect_typosquatting(features['domain'])
                if typosquat:
                    features['typosquatting'] = typosquat
            
            # Redirect analysis
            features.update(self._analyze_redirects(url))
            
            # Optional: Domain age check (WHOIS)
            if self.enable_whois:
                domain_to_check = features.get('registered_domain', '')
                if domain_to_check:
                    features.update(self._check_domain_age(domain_to_check))
            
            # Optional: DNSSEC validation
            if self.enable_dnssec:
                domain_to_check = features.get('registered_domain', '')
                if domain_to_check:
                    features['has_dnssec'] = self._check_dnssec(domain_to_check)
            
            # Calculate overall risk score
            features['risk_score'] = self._calculate_risk_score(features)
            features['risk_level'] = self._categorize_risk(features['risk_score'])
            
            # Add confidence score (how certain we are about the result)
            features['confidence'] = self._calculate_confidence(features)
            
            # Add threat categories
            features['threat_categories'] = self._identify_threat_categories(features)
            
        except Exception as e:
            features['error'] = str(e)
            features['risk_score'] = 0.5  # Neutral score on error
            features['risk_level'] = 'unknown'
            features['confidence'] = 0.0
            features['threat_categories'] = []
        
        # Add analysis time
        features['analysis_time'] = time.time() - start_time
        
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
            
            # Subdomain analysis - fix empty string issue
            ext = tldextract.extract(url)
            subdomain = ext.subdomain
            features['subdomain'] = subdomain
            
            # Properly count subdomains (ignore empty parts)
            subdomain_parts = [part for part in subdomain.split('.') if part]
            features['subdomain_count'] = len(subdomain_parts)
            features['has_www'] = 'www' in subdomain_parts
            
            # Port number - IPv6 safe parsing
            features['has_port'] = False
            features['port_number'] = None
            
            if ':' in hostname:
                try:
                    # IPv6 format: [2001:db8::1]:8080
                    if hostname.startswith('[') and ']:' in hostname:
                        port_part = hostname.split(']:')[-1]
                        features['has_port'] = True
                        features['port_number'] = int(port_part)
                    # Regular IPv4/domain: example.com:8080
                    elif not hostname.startswith('['):
                        parts = hostname.rsplit(':', 1)
                        if len(parts) == 2 and parts[1].isdigit():
                            features['has_port'] = True
                            features['port_number'] = int(parts[1])
                except (ValueError, IndexError):
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

    def _parse_cert_date(self, date_str: str) -> Optional[datetime]:
        """
        Parse SSL certificate date with multiple format support
        Handles various timezone and spacing formats
        """
        if not date_str:
            return None
        
        # Try multiple common formats
        formats = [
            '%b %d %H:%M:%S %Y GMT',      # Standard format
            '%b  %d %H:%M:%S %Y GMT',     # Double space (sometimes happens)
            '%b %d %H:%M:%S %Y',           # No timezone
            '%b %d %H:%M:%S %Y %Z',        # Generic timezone
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        
        # Last resort: remove timezone part and try
        try:
            date_without_tz = date_str.rsplit(' ', 1)[0]
            return datetime.strptime(date_without_tz, '%b %d %H:%M:%S %Y')
        except ValueError:
            return None

    def _check_ssl_certificate(self, url: str) -> Dict:
        """
        Check SSL certificate validity
        """
        features = {
            'uses_https': False,
            'valid_ssl': False,
            'ssl_issuer': None,
            'ssl_expires': None,
            'ssl_age_days': None,
            'ssl_checked': False  # Track if SSL was actually checked
        }
        
        try:
            parsed = urlparse(url)
            features['uses_https'] = parsed.scheme == 'https'
            
            if not features['uses_https']:
                return features
            
            hostname = parsed.hostname
            if not hostname:
                return features
            
            # Get SSL certificate with proper timeout handling
            context = ssl.create_default_context()
            # Don't verify for phishing detection (we want to analyze bad certs too)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            try:
                with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                    sock.settimeout(self.timeout)  # Extra timeout for SSL handshake
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        ssock.settimeout(self.timeout)
                        cert = ssock.getpeercert()
                        
                        if cert:
                            features['valid_ssl'] = True
                            features['ssl_checked'] = True
                            
                            # Fix SSL issuer parsing
                            issuer_dict = {}
                            for item in cert.get('issuer', []):
                                for key, value in item:
                                    issuer_dict[key] = value
                            features['ssl_issuer'] = issuer_dict
                            
                            # Parse expiration date - handle timezone properly
                            not_after = cert.get('notAfter')
                            if not_after:
                                expire_date = self._parse_cert_date(not_after)
                                
                                if expire_date:
                                    features['ssl_expires'] = expire_date.isoformat()
                                    
                                    # Calculate certificate age
                                    not_before = cert.get('notBefore')
                                    if not_before:
                                        issue_date = self._parse_cert_date(not_before)
                                        if issue_date:
                                            features['ssl_age_days'] = (datetime.now() - issue_date).days
                                    
                                    # Check if certificate is about to expire
                                    days_until_expire = (expire_date - datetime.now()).days
                                    features['ssl_expires_soon'] = days_until_expire < 30
                                    features['ssl_is_expired'] = days_until_expire < 0
                        else:
                            features['ssl_error'] = 'No certificate provided'
                            features['valid_ssl'] = False
            except socket.gaierror as e:
                features['ssl_error'] = f'DNS Error: {str(e)}'
                features['valid_ssl'] = False
                    
        except ssl.SSLError as e:
            features['ssl_error'] = 'SSL Error: ' + str(e)
            features['valid_ssl'] = False
            features['ssl_checked'] = True  # Checked but failed
        except socket.timeout:
            features['ssl_error'] = 'Connection timeout'
        except ConnectionRefusedError:
            features['ssl_error'] = 'Connection refused'
        except Exception as e:
            features['ssl_error'] = f'Error: {str(e)}'
        
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
            
            # Check for IP address instead of domain - IPv6 safe
            clean_hostname = hostname.split(':')[0].strip('[]')
            features['uses_ip_address'] = self._is_ip_address(clean_hostname)
            
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
            # FIXED: Consistent empty part filtering
            subdomain_parts = [part for part in ext.subdomain.split('.') if part] if ext.subdomain else []
            features['excessive_subdomains'] = len(subdomain_parts) > 3
            
        except Exception as e:
            features['pattern_error'] = str(e)
        
        return features

    def _analyze_redirects(self, url: str) -> Dict:
        """
        Analyze redirect chains with fallback to GET
        """
        features = {
            'redirect_count': 0,
            'final_url': url,
            'has_redirects': False,
            'redirect_chain': []
        }
        
        try:
            # Try HEAD first (faster)
            try:
                response = requests.head(
                    url,
                    allow_redirects=True,
                    timeout=self.timeout,
                    verify=False
                )
            except requests.exceptions.RequestException:
                # Fallback to GET with streaming (some servers don't support HEAD)
                with requests.get(
                    url,
                    allow_redirects=True,
                    timeout=self.timeout,
                    verify=False,
                    stream=True
                ) as response:
                    pass  # Just get metadata, context manager handles closing
            
            # Check redirect history
            if response.history:
                features['has_redirects'] = True
                features['redirect_count'] = len(response.history)
                features['final_url'] = response.url
                
                # Limit redirect chain to prevent memory issues
                features['redirect_chain'] = [r.url for r in response.history[:10]]
                if len(response.history) > 10:
                    features['redirect_chain'].append('... (truncated)')
                
                # Check if redirect changes domain - with error handling
                try:
                    original_domain = tldextract.extract(url).registered_domain
                    final_domain = tldextract.extract(response.url).registered_domain
                    features['redirect_changes_domain'] = (
                        original_domain != final_domain and 
                        original_domain and final_domain  # Both must be valid
                    )
                except Exception:
                    features['redirect_changes_domain'] = False
                
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
        Enhanced homograph attack detection with Unicode category checking
        Optimized for performance
        """
        # Quick pre-check: if all ASCII, only check lookalike map
        has_non_ascii = False
        for char in text:
            if ord(char) > 127:
                has_non_ascii = True
                break
            # Check known lookalike map for ASCII-compatible chars
            if char in self.homograph_map:
                return True
        
        # If no non-ASCII, we're done
        if not has_non_ascii:
            return False
        
        # Detailed check for non-ASCII characters
        for char in text:
            if ord(char) > 127:
                try:
                    # Get Unicode category first (faster than name lookup)
                    category = unicodedata.category(char)
                    if category.startswith('L'):  # Letter category
                        # Only do expensive name lookup for letters
                        char_name = unicodedata.name(char, '')
                        # Check for suspicious scripts
                        suspicious_scripts = ['CYRILLIC', 'GREEK', 'ARABIC', 'HEBREW']
                        if any(script in char_name for script in suspicious_scripts):
                            return True
                except ValueError:
                    # Character has no name, potentially suspicious
                    pass
            
            # Check known lookalike map
            if char in self.homograph_map:
                return True
        
        return False
    
    def _detect_typosquatting(self, domain: str) -> Optional[str]:
        """
        Detect typosquatting (deliberate misspellings of popular brands)
        Examples: googel.com, paypa1.com, amazom.com
        """
        import difflib
        
        # Common typosquatting targets
        major_brands = [
            'google', 'paypal', 'amazon', 'microsoft', 'apple',
            'facebook', 'instagram', 'twitter', 'netflix', 'linkedin',
            'youtube', 'gmail', 'yahoo', 'ebay', 'spotify'
        ]
        
        domain_lower = domain.lower()
        
        for brand in major_brands:
            # Skip if exact match (legitimate)
            if domain_lower == brand:
                continue
            
            # Calculate similarity ratio
            similarity = difflib.SequenceMatcher(None, domain_lower, brand).ratio()
            
            # High similarity but not exact = possible typosquatting
            # 0.75-0.99 range catches most typos: googel, paypa1, etc.
            if 0.75 <= similarity < 1.0:
                return f"{brand} (typosquatting)"
        
        return None

    def _detect_brand_impersonation(self, url: str) -> Optional[str]:
        """
        Detect brand impersonation attempts with improved whitelist checking
        Returns the impersonated brand name if detected, None otherwise
        """
        url_lower = url.lower()
        parsed = urlparse(url_lower)
        ext = tldextract.extract(url)
        domain = ext.domain.lower()
        subdomain = ext.subdomain.lower()
        path = parsed.path.lower()
        registered_domain = ext.registered_domain.lower()
        
        for brand in self.brand_keywords:
            if brand not in url_lower:
                continue
            
            # Check if it's a whitelisted domain for this brand
            # FIXED: Proper whitelist checking to prevent paypal.com.evil.com bypass
            if brand in self.whitelisted_domains:
                whitelisted = self.whitelisted_domains[brand]
                # Extra security: ensure registered_domain exists and is valid
                if registered_domain and registered_domain.strip() and registered_domain in whitelisted:
                    continue  # Legitimate domain, skip
            
            # Case 1: Brand in domain but with modifications (e.g., paypal-secure.com)
            if brand in domain:
                # If exact match, it might be legitimate
                if domain == brand:
                    # But check if TLD is suspicious
                    if ('.' + ext.suffix) in self.suspicious_tlds:
                        return brand  # paypal.tk is suspicious
                    continue  # Likely legitimate
                else:
                    # Brand is part of domain but not exact (paypal-verify, secure-paypal)
                    return brand
            
            # Case 2: Brand in subdomain (secure-paypal.evil.com)
            if brand in subdomain:
                # Common pattern: legitimate brands use simple subdomains
                # Suspicious: paypal-secure.example.com, secure.paypal.example.com
                subdomain_parts = subdomain.split('.')
                for part in subdomain_parts:
                    if brand in part and part != brand:
                        return brand
            
            # Case 3: Brand in path (evil.com/paypal/login)
            if brand in path:
                # Suspicious if brand appears in path but not in domain
                path_parts = path.split('/')
                for part in path_parts:
                    if brand in part:
                        return brand
            
            # Case 4: Multiple security/urgency keywords with brand
            security_keywords = ['secure', 'verify', 'account', 'update', 'confirm', 
                               'suspended', 'locked', 'alert', 'warning', 'urgent']
            keyword_count = sum(1 for kw in security_keywords if kw in url_lower)
            if keyword_count >= 2 and brand in url_lower:
                return brand
        
        return None

    def _calculate_risk_score(self, features: Dict) -> float:
        """
        Calculate overall risk score (0-1, higher is more suspicious)
        FIXED: Proper normalization with separate positive/negative scores
        """
        positive_score = 0.0
        negative_score = 0.0
        max_positive = 0.0
        max_negative = 0.0
        
        # Positive risk indicators (bad signs)
        positive_checks = [
            ('is_ip_address', 0.15),
            ('has_at_symbol', 0.10),
            ('has_homograph', 0.15),
            ('brand_impersonation', 0.12),
            ('typosquatting', 0.12),  # NEW: Typosquatting detection
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
        
        for feature, weight in positive_checks:
            if feature in features:
                max_positive += weight
                if features[feature]:
                    positive_score += weight
        
        # Negative risk indicators (good signs)
        # HTTPS with valid SSL is a strong positive indicator
        if features.get('uses_https') and features.get('valid_ssl'):
            max_negative += 0.10
            negative_score += 0.10
        elif not features.get('uses_https'):
            # No HTTPS is bad
            max_positive += 0.08
            positive_score += 0.08
        
        # Entropy-based checks (high entropy = suspicious)
        max_positive += 0.05
        if features.get('url_entropy', 0) > 4.5:
            positive_score += 0.05
        
        # Suspicious keyword count
        max_positive += 0.10
        keyword_count = features.get('suspicious_keyword_count', 0)
        if keyword_count > 0:
            positive_score += min(keyword_count * 0.03, 0.10)
        
        # Calculate final normalized score
        total_max = max_positive + max_negative
        if total_max > 0:
            # (Positive risks - Negative risks) normalized to 0-1
            raw_score = (positive_score - negative_score) / total_max
            # Ensure it stays in valid range
            score = max(0.0, min(1.0, raw_score))
        else:
            score = 0.5  # Neutral if no indicators
        
        return score

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
    
    def _calculate_confidence(self, features: Dict) -> float:
        """
        Calculate confidence score for the risk assessment
        Higher confidence = more reliable indicators present
        
        Returns:
            Confidence score from 0.0 to 1.0
        """
        confidence_factors = 0
        total_factors = 0
        
        # Strong indicators increase confidence
        strong_indicators = [
            'is_ip_address',
            'has_at_symbol', 
            'has_homograph',
            'ssl_is_expired',
            'uses_https'
        ]
        
        for indicator in strong_indicators:
            if indicator in features and features[indicator] is not None:
                total_factors += 1
                if features[indicator]:
                    confidence_factors += 1
        
        # Having valid SSL increases confidence in safety
        if features.get('uses_https') and features.get('valid_ssl'):
            confidence_factors += 2
            total_factors += 2
        
        # Multiple suspicious patterns increase confidence in threat
        suspicious_count = sum([
            features.get('brand_impersonation') is not None,
            features.get('is_suspicious_tld', False),
            features.get('excessive_subdomains', False),
            features.get('suspicious_keyword_count', 0) > 2
        ])
        
        if suspicious_count > 0:
            confidence_factors += suspicious_count
            total_factors += suspicious_count
        
        # Calculate confidence
        if total_factors > 0:
            confidence = confidence_factors / total_factors
        else:
            confidence = 0.5  # Neutral if no strong indicators
        
        return round(confidence, 3)
    
    def _identify_threat_categories(self, features: Dict) -> List[str]:
        """
        Identify specific threat categories present in the URL
        
        Returns:
            List of threat category strings
        """
        categories = []
        
        if features.get('brand_impersonation'):
            categories.append('brand_impersonation')
        
        if features.get('is_ip_address') or features.get('uses_ip_address'):
            categories.append('ip_address_abuse')
        
        if features.get('has_homograph'):
            categories.append('homograph_attack')
        
        if features.get('is_suspicious_tld'):
            categories.append('suspicious_tld')
        
        if features.get('has_at_symbol'):
            categories.append('url_obfuscation')
        
        if features.get('ssl_is_expired') or (not features.get('uses_https')):
            categories.append('insecure_connection')
        
        if features.get('redirect_changes_domain'):
            categories.append('suspicious_redirect')
        
        if features.get('is_shortened'):
            categories.append('url_shortener')
        
        if features.get('suspicious_keyword_count', 0) > 2:
            categories.append('social_engineering')
        
        if features.get('typosquatting'):
            categories.append('typosquatting')
        
        return categories

    def get_summary(self, features: Dict) -> str:
        """
        Generate human-readable summary of analysis
        """
        risk_score = features.get('risk_score', 0)
        risk_level = features.get('risk_level', 'unknown')
        confidence = features.get('confidence', 0)
        threat_categories = features.get('threat_categories', [])
        
        summary = f"URL Risk Analysis Summary:\n"
        summary += f"Risk Score: {risk_score:.2f} ({risk_level.upper()})\n"
        summary += f"Confidence: {confidence:.2f} (Analysis reliability)\n"
        summary += f"Analysis Time: {features.get('analysis_time', 0):.3f}s\n\n"
        
        if threat_categories:
            summary += "Threat Categories:\n"
            category_names = {
                'brand_impersonation': 'Brand/Trademark Impersonation',
                'ip_address_abuse': 'IP Address Used (Not Domain)',
                'homograph_attack': 'Homograph/Lookalike Characters',
                'suspicious_tld': 'Suspicious Top-Level Domain',
                'url_obfuscation': 'URL Obfuscation Techniques',
                'insecure_connection': 'Insecure/No HTTPS Connection',
                'suspicious_redirect': 'Suspicious Redirection',
                'url_shortener': 'URL Shortener Service',
                'social_engineering': 'Social Engineering Keywords',
                'typosquatting': 'Typosquatting (Brand Misspelling)'
            }
            for cat in threat_categories:
                summary += f"  🚨 {category_names.get(cat, cat)}\n"
            summary += "\n"
        
        summary += "Suspicious Indicators:\n"
        
        if features.get('is_ip_address'):
            summary += "  ⚠️ URL uses IP address instead of domain name\n"
        if features.get('has_at_symbol'):
            summary += "  ⚠️ URL contains @ symbol (can hide real domain)\n"
        if features.get('has_homograph'):
            summary += "  ⚠️ URL contains lookalike characters (homograph attack)\n"
        if features.get('brand_impersonation'):
            summary += f"  ⚠️ Possible brand impersonation: {features['brand_impersonation']}\n"
        if features.get('typosquatting'):
            summary += f"  ⚠️ Typosquatting detected: {features['typosquatting']}\n"
        if features.get('is_suspicious_tld'):
            summary += f"  ⚠️ Suspicious TLD: {features.get('tld')}\n"
        if features.get('very_long_url'):
            summary += f"  ⚠️ Very long URL ({features.get('url_length')} characters)\n"
        if not features.get('uses_https'):
            summary += "  ⚠️ No HTTPS encryption\n"
        elif not features.get('valid_ssl'):
            summary += "  ⚠️ Invalid or expired SSL certificate\n"
        if features.get('redirect_changes_domain'):
            summary += "  ⚠️ Redirect changes domain\n"
        
        if risk_level == 'safe' and not threat_categories:
            summary += "  ✅ No major suspicious indicators found\n"
        
        return summary
    
    def _check_domain_age(self, domain: str) -> Dict:
        """
        Check domain age using WHOIS (optional feature)
        Requires: pip install python-whois
        """
        features = {
            'domain_age_days': -1,
            'domain_age_suspicious': False
        }
        
        try:
            import whois
            w = whois.whois(domain)
            
            if w and w.creation_date:
                # Handle list or single date
                if isinstance(w.creation_date, list):
                    creation = w.creation_date[0]
                else:
                    creation = w.creation_date
                
                if creation:
                    # Make creation naive if it's timezone-aware (WHOIS compatibility)
                    if hasattr(creation, 'tzinfo') and creation.tzinfo is not None:
                        creation = creation.replace(tzinfo=None)
                    
                    age_days = (datetime.now() - creation).days
                    features['domain_age_days'] = age_days
                    
                    # Domains less than 30 days old are suspicious
                    features['domain_age_suspicious'] = age_days < 30
                    
        except ImportError:
            features['whois_error'] = 'python-whois not installed'
        except Exception as e:
            features['whois_error'] = str(e)
        
        return features
    
    def _check_dnssec(self, domain: str) -> bool:
        """
        Check if domain has DNSSEC enabled (optional feature)
        Requires: pip install dnspython
        """
        try:
            import dns.resolver
            import dns.flags
            
            resolver = dns.resolver.Resolver()
            resolver.use_edns(0, dns.flags.DO, 4096)
            
            try:
                answers = resolver.resolve(domain, 'A')
                # Check if Authenticated Data flag is set
                return bool(answers.response.flags & dns.flags.AD)
            except:
                return False
                
        except ImportError:
            return False
        except Exception:
            return False


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
