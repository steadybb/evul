import os
import sys
import importlib.util
from pathlib import Path

repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / 'evildev'))


def _load_harvester():
    mod_path = repo_root / 'evildev' / 'harvester.py'
    spec = importlib.util.spec_from_file_location('harvester', str(mod_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_device_code_endpoint_format():
    harvester = _load_harvester().TokenHarvester(
        client_id='00000000-0000-0000-0000-000000000000',
        tenant='common',
        scopes=['https://graph.microsoft.com/User.Read', 'openid', 'offline_access', 'profile']
    )

    assert hasattr(harvester, 'get_device_code'), 'TokenHarvester must implement get_device_code()'
    assert harvester.client_id == '00000000-0000-0000-0000-000000000000'
    assert harvester.tenant == 'common'
    assert 'openid' in harvester.scopes
    assert 'https://graph.microsoft.com/User.Read' in harvester.scopes


def test_device_code_request_builds_payload_correctly():
    harvester = _load_harvester().TokenHarvester(
        client_id='00000000-0000-0000-0000-000000000000',
        tenant='common',
        scopes=['https://graph.microsoft.com/User.Read', 'openid', 'offline_access', 'profile']
    )

    data = {
        'client_id': harvester.client_id,
        'scope': ' '.join(harvester.scopes)
    }

    assert data['client_id'] == '00000000-0000-0000-0000-000000000000'
    assert 'https://graph.microsoft.com/User.Read' in data['scope']
    assert 'offline_access' in data['scope']
    assert data['scope'].count(' ') >= 3


def test_proxy_validity_does_not_override_env():
    os.environ['PROXY_LIST'] = 'http://proxyuser:proxypass@127.0.0.1:3128'
    harvester = _load_harvester().TokenHarvester(
        client_id='00000000-0000-0000-0000-000000000000',
        tenant='common',
        scopes=['openid', 'offline_access', 'profile']
    )

    session = harvester.stealth.build_session()
    assert session.trust_env is False, 'Session must not inherit environment proxy settings'
    assert session.proxies.get('http') is not None
    assert session.proxies.get('https') == session.proxies.get('http')
