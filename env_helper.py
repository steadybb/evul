#!/usr/bin/env python3
"""
Environment configuration helper for Device Code Harvester
Provides utilities for loading and validating environment configurations
"""

import os
import json
import sys
from pathlib import Path
from dotenv import load_dotenv


def load_environment(env_file=None):
    """
    Load environment from .env file
    
    Args:
        env_file: Specific .env file to load (default: .env)
    
    Returns:
        dict: Environment variables
    """
    if env_file is None:
        env_file = '.env'
    
    env_path = Path(env_file)
    if not env_path.exists():
        print(f"⚠️  {env_file} not found. Using system environment variables.")
        return dict(os.environ)
    
    load_dotenv(env_file)
    print(f"✅ Loaded environment from {env_file}")
    return dict(os.environ)


def validate_config():
    """
    Validate required configuration settings
    
    Returns:
        bool: True if config is valid
    """
    required = ['CLIENT_ID']
    optional_but_important = ['EXFIL_CONFIG', 'WORM_ENABLED']
    
    missing = []
    for var in required:
        if not os.environ.get(var):
            missing.append(var)
    
    if missing:
        print(f"❌ Missing required configuration: {', '.join(missing)}")
        return False
    
    print("✅ Required configuration present")
    
    # Warn about important optional settings
    for var in optional_but_important:
        if not os.environ.get(var):
            print(f"⚠️  Optional but important: {var} is not set")
    
    return True


def print_active_config():
    """Print currently active configuration (non-sensitive values)"""
    
    sensitive_keys = ['AUTH_PASS', 'ENCRYPTION_KEY', 'TELEGRAM_BOT_TOKEN', 
                      'AWS_SECRET_ACCESS_KEY', 'WORM_MASTER_KEY']
    
    print("\n" + "="*70)
    print("ACTIVE CONFIGURATION")
    print("="*70)
    
    categories = {
        'Server': ['PORT', 'FLASK_DEBUG', 'DEBUG'],
        'Auth': ['REQUIRE_AUTH', 'AUTH_USER'],
        'Azure': ['CLIENT_ID', 'TENANT'],
        'Worm': ['WORM_ENABLED', 'WORM_MAX_DEPTH', 'WORM_MAX_TARGETS'],
        'Exfil': ['EXFIL_CONFIG', 'EXFIL_OUTPUT_DIR'],
        'Proxy': ['PROXY_LIST', 'DISABLE_SSL_VERIFY'],
        'Playwright': ['PLAYWRIGHT'],
    }
    
    for category, keys in categories.items():
        print(f"\n{category}:")
        for key in keys:
            value = os.environ.get(key, '(not set)')
            if key in sensitive_keys:
                value = '***REDACTED***' if value != '(not set)' else value
            print(f"  {key}: {value}")
    
    print("\n" + "="*70 + "\n")


def generate_encryption_key():
    """Generate a new AES-256 encryption key"""
    import os
    key = os.urandom(32).hex()
    print(f"Generated ENCRYPTION_KEY: {key}")
    print("Add this to your .env file:")
    print(f"ENCRYPTION_KEY={key}")
    return key


def list_environments():
    """List available environment files"""
    env_files = Path('.').glob('.env*')
    print("\nAvailable environment files:")
    for env_file in sorted(env_files):
        size = env_file.stat().st_size
        print(f"  {env_file.name} ({size} bytes)")


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Environment configuration helper')
    parser.add_argument('--env', default='.env', help='Environment file to load')
    parser.add_argument('--validate', action='store_true', help='Validate configuration')
    parser.add_argument('--show', action='store_true', help='Show active configuration')
    parser.add_argument('--gen-key', action='store_true', help='Generate encryption key')
    parser.add_argument('--list', action='store_true', help='List available environments')
    
    args = parser.parse_args()
    
    if args.list:
        list_environments()
    elif args.gen_key:
        generate_encryption_key()
    else:
        load_environment(args.env)
        
        if args.validate:
            if validate_config():
                print("\n✅ Configuration is valid")
            else:
                print("\n❌ Configuration validation failed")
                sys.exit(1)
        
        if args.show:
            print_active_config()
