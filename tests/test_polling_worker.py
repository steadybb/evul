import os
import sys
import importlib.util
import queue
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


def test_polling_worker_success():
    app_mod = _load_app_module()

    # Prepare session structure expected by polling_worker
    session_id = 'poll-success'
    app_mod.sessions[session_id] = {
        'client_id': 'cid',
        'tenant': 'common',
        'scopes': ['openid'],
        'refresh': False,
        'detect_ca': False,
        'max_endpoints': 1,
        'created_at': 0,
        'status': 'initializing',
        'device_code_data': None,
        'token': None,
        'user_info': {},
        'cookies': [],
        'polling_active': False,
        'queue': queue.Queue(),
        'results': {}
    }

    class FakeHarvester:
        def poll_for_token(self, device_code):
            return {'success': True, 'access_token': 'access-123'}

    device_code_data = {'device_code': 'device-123', 'interval': 0}

    # Run polling_worker synchronously
    app_mod.polling_worker(session_id, FakeHarvester(), device_code_data)

    sess = app_mod.sessions[session_id]
    assert sess['token'] == 'access-123'
    # Ensure a token_obtained event was queued
    events = []
    while not sess['queue'].empty():
        events.append(sess['queue'].get_nowait())
    assert any(e.get('type') == 'token_obtained' for e in events), f"Events: {events}"
    assert sess['polling_active'] is False


def test_polling_worker_error():
    app_mod = _load_app_module()

    session_id = 'poll-error'
    app_mod.sessions[session_id] = {
        'client_id': 'cid',
        'tenant': 'common',
        'scopes': ['openid'],
        'refresh': False,
        'detect_ca': False,
        'max_endpoints': 1,
        'created_at': 0,
        'status': 'initializing',
        'device_code_data': None,
        'token': None,
        'user_info': {},
        'cookies': [],
        'polling_active': False,
        'queue': queue.Queue(),
        'results': {}
    }

    class BrokenHarvester:
        def poll_for_token(self, device_code):
            raise RuntimeError('poll failure')

    device_code_data = {'device_code': 'device-err', 'interval': 0}

    app_mod.polling_worker(session_id, BrokenHarvester(), device_code_data)

    sess = app_mod.sessions[session_id]
    # Ensure an error event was queued
    events = []
    while not sess['queue'].empty():
        events.append(sess['queue'].get_nowait())
    assert any(e.get('type') == 'error' for e in events), f"Events: {events}"
    assert sess['polling_active'] is False
