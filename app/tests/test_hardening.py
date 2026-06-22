"""Tests for the public-release hardening: feed limit clamp, /ingest body cap,
and the SQLite WAL pragma."""
from contextlib import closing


def _ingest(client, **over):
    payload = {"priority": "Warning", "rule": "R", "output": "out", "hostname": "h1"}
    payload.update(over)
    r = client.post("/ingest", json=payload)
    assert r.status_code == 200


def _card_count(html: str) -> int:
    # One <details class="card ..."> renders per event in _feed.html.
    return html.count('class="card')


def test_feed_negative_limit_is_clamped(client):
    # SQLite reads a negative LIMIT as "no limit" (whole table); the clamp
    # floors it at 1 so ?limit=-1 can't dump everything.
    for i in range(3):
        _ingest(client, rule=f"R{i}")
    r = client.get("/feed", params={"limit": -1})
    assert r.status_code == 200
    assert _card_count(r.text) == 1


def test_feed_huge_limit_is_bounded(client):
    # The clamp ceiling is 1000, comfortably above our 3 events -> all returned,
    # but a 10-million request can never allocate the whole table into memory.
    for i in range(3):
        _ingest(client, rule=f"R{i}")
    r = client.get("/feed", params={"limit": 10_000_000})
    assert r.status_code == 200
    assert _card_count(r.text) == 3


def test_ingest_rejects_oversized_body(client, app_mod, monkeypatch):
    # Shrink the cap so the test payload trips it without sending a real MiB.
    monkeypatch.setattr(app_mod, "MAX_INGEST_BYTES", 100)
    r = client.post("/ingest", json={"rule": "R", "output": "x" * 500})
    assert r.status_code == 413


def test_db_uses_wal(app_mod):
    app_mod.init_db()
    with closing(app_mod.db()) as conn:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"
