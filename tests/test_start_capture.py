import os
import sys
import importlib.util
from pathlib import Path

repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / 'evildev'))


def _load_app_module():
    os.environ['REQUIRE_AUTH'] = 'false'
    os.environ['WORM_ENABLED'] = 'false'
    os.environ['PROJECT_DB_PATH'] = str(repo_root / 'tests' / 'temp_test_project_data.db')
    os.environ['DATABASE_URL'] = ''
    os.environ['PROXY_LIST'] = ''
    app_path = repo_root / 'evildev' / 'app.py'
    spec = importlib.util.spec_from_file_location('evilapp', str(app_path))
    app_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app_mod)
    return app_mod


def test_start_capture_integration_flow():
    app_mod = _load_app_module()

    class FakeHarvester:
        def __init__(self, client_id, tenant='common', scopes=None, stealth=None):
            self.client_id = client_id
            self.tenant = tenant
            self.scopes = scopes or []
            self.stealth = stealth

        def get_device_code(self):
            return {
                'user_code': 'TEST-CODE-123',
                'device_code': 'device-code-123',
                'verification_uri': 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
                'interval': 5
            }

    def no_op_polling_worker(session_id, harvester, device_code_data):
        # Avoid real polling in the integration test
        app_mod.sessions[session_id]['polling_active'] = False

    app_mod.TokenHarvester = FakeHarvester
    app_mod.polling_worker = no_op_polling_worker

    client = app_mod.app.test_client()
    payload = {
        'client_id': '00000000-0000-0000-0000-000000000000',
        'tenant': 'common',
        'scope': 'openid offline_access profile',
        'max_endpoints': 4,
        'refresh': False,
        'detect_ca': False
    }

    response = client.post('/api/start-capture', json=payload)
    assert response.status_code == 200, f'Expected 200 OK, got {response.status_code}: {response.data}'

    data = response.get_json()
    assert data is not None, 'Response should contain JSON'
    assert data['user_code'] == 'TEST-CODE-123', f"Unexpected user_code: {data.get('user_code')!r}"
    assert data['verification_uri'] == 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode', f"Unexpected verification_uri: {data.get('verification_uri')!r}"
    assert 'session_id' in data, f"session_id missing from response: {data!r}"

    session_id = data['session_id']
    assert session_id in app_mod.sessions, 'Session should be persisted in app.sessions'
    assert app_mod.sessions[session_id]['device_code_data']['user_code'] == 'TEST-CODE-123'
    assert app_mod.sessions[session_id]['tenant'] == 'common'
    scopes = app_mod.sessions[session_id]['scopes']
    assert all(scope in scopes for scope in ['openid', 'offline_access', 'profile']), f"Missing expected scopes: {scopes}"
    assert isinstance(scopes, list), f"Scopes should be a list, got {type(scopes).__name__}"
