import threading
import os
from pathlib import Path
from typing import List, Optional

_lock = threading.Lock()
_proxies: List[str] = []
_index = 0


def load_proxies_from_env_or_file(env_key: str = 'PROXY_LIST', file_path: Optional[str] = None) -> List[str]:
    """Load proxies from `PROXY_LIST` env var or from a proxy.txt file.
    Normalizes proxies to include scheme (defaults to http:// when missing).
    Returns the list of proxies stored in the manager.
    """
    global _proxies, _index
    proxies: List[str] = []

    # First try environment
    env_val = os.environ.get(env_key, '') or ''
    if env_val:
        parts = [p.strip() for p in env_val.split(',') if p.strip()]
        proxies.extend(parts)

    # Fallback to file if no env proxies
    if not proxies and file_path:
        p = Path(file_path)
        if p.exists():
            with p.open('r', encoding='utf-8') as fh:
                for line in fh:
                    ln = line.strip()
                    if not ln or ln.startswith('#'):
                        continue
                    proxies.append(ln)

    # Normalize: prepend http:// when missing scheme
    normalized = []
    for ln in proxies:
        if ln.startswith('http://') or ln.startswith('https://') or ln.startswith('socks'):
            normalized.append(ln)
        else:
            normalized.append('http://' + ln)

    with _lock:
        _proxies = normalized
        _index = 0

    return list(_proxies)


def get_proxy_count() -> int:
    with _lock:
        return len(_proxies)


def get_current_proxy() -> Optional[str]:
    """Return the next proxy that would be returned without advancing rotation."""
    with _lock:
        if not _proxies:
            return None
        return _proxies[_index % len(_proxies)]


def get_proxy_index() -> int:
    """Return the current rotation index for the next proxy."""
    with _lock:
        return _index


def get_next_proxy() -> Optional[str]:
    """Return the next proxy in round-robin order, or None if none configured."""
    global _index
    with _lock:
        if not _proxies:
            return None
        proxy = _proxies[_index % len(_proxies)]
        _index = (_index + 1) % len(_proxies)
        return proxy


def get_all_proxies() -> List[str]:
    with _lock:
        return list(_proxies)
