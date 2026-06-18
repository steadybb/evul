import os
import sys
from pathlib import Path
import importlib.util


def _load_proxy_manager():
    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root))
    sys.path.insert(0, str(repo_root / 'evildev'))
    mod_path = repo_root / 'evildev' / 'proxy_manager.py'
    spec = importlib.util.spec_from_file_location('proxy_manager', str(mod_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / 'evildev'))

proxy_manager = _load_proxy_manager()


def test_load_from_env_and_rotation():
    os.environ['PROXY_LIST'] = 'http://user:pass@1.2.3.4:3129,5c5z3gp0syt8:xdjeo7txix5rnn7@45.3.37.235:3129'
    loaded = proxy_manager.load_proxies_from_env_or_file('PROXY_LIST')
    assert len(loaded) == 2
    p1 = proxy_manager.get_next_proxy()
    p2 = proxy_manager.get_next_proxy()
    p3 = proxy_manager.get_next_proxy()
    assert p1 is not None
    assert p2 is not None
    # round robin: p3 should equal p1 again
    assert p3 == p1


def test_load_from_file():
    # Ensure env not set
    os.environ.pop('PROXY_LIST', None)
    data = 'user:pass@10.0.0.1:3129\n# comment\n5c5z3gp0syt8:xdjeo7txix5rnn7@45.3.37.235:3129\n'
    import tempfile
    with tempfile.NamedTemporaryFile('w+', delete=False, suffix='.txt') as tf:
        tf.write(data)
        tf.flush()
        path = tf.name
    loaded = proxy_manager.load_proxies_from_env_or_file('PROXY_LIST', str(path))
    assert len(loaded) == 2
    assert loaded[0].startswith('http://')


def test_core_engine_loads_root_proxy_file():
    os.environ.pop('PROXY_LIST', None)
    root_proxy_file = Path(__file__).resolve().parents[1] / 'proxy.txt'
    assert root_proxy_file.exists(), 'Expected proxy.txt in the repository root'

    core_path = Path(__file__).resolve().parents[1] / 'evildev' / 'core.py'
    spec = importlib.util.spec_from_file_location('core', str(core_path))
    core = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(core)

    engine = core.StealthEngine()
    assert engine.proxy_list, 'StealthEngine should load proxies from root proxy.txt when PROXY_LIST is unset'
    assert len(engine.proxy_list) == len([p for p in engine.proxy_list if p])
