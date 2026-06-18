import requests
from requests.auth import HTTPBasicAuth
import time

url = 'http://127.0.0.1:5000/api/start-capture'
payload = {
    'client_id': '964ba4e2-1342-4c6a-acf1-2c0d16031bd3',
    'tenant': '32de313a-07a4-41dd-a867-f7c9eb1b50a6',
    'scope': 'openid offline_access profile',
    'max_endpoints': 4,
    'refresh': True,
    'detect_ca': True
}
for i in range(3):
    print('call', i+1)
    try:
        r = requests.post(url, json=payload, auth=HTTPBasicAuth('operator', 'StrongPassword123!'), timeout=60)
        print(r.status_code)
        print(r.text)
    except Exception as e:
        print('error', type(e).__name__, e)
    time.sleep(1)
