import importlib
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture
def app_mod(tmp_path, monkeypatch):
    """Reload main with an isolated tmp SQLite DB."""
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.db"))
    import main
    importlib.reload(main)
    return main


@pytest.fixture
def client(app_mod):
    from fastapi.testclient import TestClient
    with TestClient(app_mod.app) as c:   # lifespan -> init_db()
        yield c


@pytest.fixture
def insert(app_mod):
    """Insert an event with an explicit received_at (UTC datetime)."""
    from contextlib import closing
    app_mod.init_db()

    def _insert(received_at: datetime, *, rule="R", priority="warning",
                hostname="h1", source="syscall", output="out", tags=None, fields=None):
        import json
        with closing(app_mod.db()) as conn:
            conn.execute(
                "INSERT INTO events (received_at, event_time, rule, priority, source, hostname, output, tags, fields)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (received_at.isoformat(), received_at.isoformat(), rule, priority,
                 source, hostname, output, json.dumps(tags or []), json.dumps(fields or {})),
            )
            conn.commit()
    return _insert
