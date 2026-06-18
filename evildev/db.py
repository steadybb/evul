#!/usr/bin/env python3
import os
import json
import sqlite3
from pathlib import Path

try:
    import psycopg2
except ImportError:
    psycopg2 = None

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SQLITE_PATH = PROJECT_ROOT / 'project_data.db'


def get_db_settings():
    db_url = os.environ.get('DATABASE_URL') or os.environ.get('PROJECT_DB_URL', '')
    db_path = Path(os.environ.get('PROJECT_DB_PATH', str(DEFAULT_SQLITE_PATH)))
    db_engine = 'postgres' if db_url else 'sqlite'
    return db_engine, db_url, db_path


def get_placeholder():
    engine, _, _ = get_db_settings()
    return '%s' if engine == 'postgres' else '?'


def connect_db():
    engine, db_url, db_path = get_db_settings()
    if engine == 'postgres':
        if psycopg2 is None:
            raise RuntimeError('Postgres is configured but psycopg2 is not installed')
        return psycopg2.connect(db_url)

    db_path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(str(db_path), check_same_thread=False)


def init_db():
    conn = connect_db()
    c = conn.cursor()
    placeholder = get_placeholder()

    c.execute('''CREATE TABLE IF NOT EXISTS runtime_overrides (
        key TEXT PRIMARY KEY,
        value TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS saved_configs (
        name TEXT PRIMARY KEY,
        config TEXT,
        created_at TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS tokens (
        email TEXT PRIMARY KEY,
        encrypted_token TEXT,
        refresh_token TEXT,
        expires_at TEXT,
        captured_at TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS targets (
        email TEXT PRIMARY KEY,
        source_email TEXT,
        depth INTEGER,
        user_code TEXT,
        device_code TEXT,
        status TEXT,
        captured_at TEXT,
        score INTEGER,
        job_title TEXT,
        relationship TEXT,
        created_at TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS sent_phish (
        email TEXT,
        timestamp TEXT,
        user_code TEXT,
        verification_uri TEXT,
        success TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS worm_stats (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at TEXT
    )''')

    conn.commit()
    return conn


def load_runtime_overrides():
    conn = connect_db()
    c = conn.cursor()
    c.execute('SELECT key, value FROM runtime_overrides')
    overrides = {row[0]: row[1] for row in c.fetchall()}
    conn.close()
    return overrides


def save_runtime_overrides(overrides: dict):
    conn = connect_db()
    c = conn.cursor()
    placeholder = get_placeholder()

    c.execute('DELETE FROM runtime_overrides')
    for key, value in overrides.items():
        c.execute(f'INSERT INTO runtime_overrides (key, value) VALUES ({placeholder}, {placeholder})', (key, str(value)))

    conn.commit()
    conn.close()
    return True


def load_saved_configs():
    conn = connect_db()
    c = conn.cursor()
    c.execute('SELECT name, config, created_at FROM saved_configs')
    configs = {}
    for name, config_text, created_at in c.fetchall():
        try:
            config = json.loads(config_text)
        except Exception:
            config = {}
        config['created_at'] = created_at
        configs[name] = config
    conn.close()
    return configs


def save_configs(configs: dict):
    conn = connect_db()
    c = conn.cursor()
    placeholder = get_placeholder()

    c.execute('DELETE FROM saved_configs')
    for name, config in configs.items():
        config_text = json.dumps(config)
        created_at = config.get('created_at', None)
        c.execute(
            f'INSERT INTO saved_configs (name, config, created_at) VALUES ({placeholder}, {placeholder}, {placeholder})',
            (name, config_text, created_at)
        )

    conn.commit()
    conn.close()
    return True
