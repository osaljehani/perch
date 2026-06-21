"""Tests for the optional ntfy critical-alert notifier wired into POST /ingest.

The raw HTTP POST is isolated in ``main.post_ntfy`` so these tests monkeypatch
it and never hit the network.
"""
from contextlib import closing


def _configure_ntfy(monkeypatch):
    monkeypatch.setenv("NTFY_URL", "https://ntfy.example.com")
    monkeypatch.setenv("NTFY_TOPIC", "falco-alerts")
    monkeypatch.setenv("NTFY_TOKEN", "tk_secrettoken")


def _record_posts(monkeypatch, app_mod, *, fail=False):
    calls = []

    async def fake_post(url, headers, data):
        calls.append({"url": url, "headers": headers, "data": data})
        if fail:
            raise RuntimeError("ntfy unreachable")

    monkeypatch.setattr(app_mod, "post_ntfy", fake_post)
    return calls


def _count_events(app_mod):
    with closing(app_mod.db()) as conn:
        return conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]


def test_critical_event_triggers_ntfy_push(client, app_mod, monkeypatch):
    _configure_ntfy(monkeypatch)
    calls = _record_posts(monkeypatch, app_mod)

    r = client.post("/ingest", json={
        "priority": "Critical",
        "rule": "Terminal shell in container",
        "output": "A shell was spawned in a container",
        "hostname": "rasp",
    })
    assert r.status_code == 200
    assert len(calls) == 1
    c = calls[0]
    assert c["url"] == "https://ntfy.example.com/falco-alerts"
    assert c["headers"]["Authorization"] == "Bearer tk_secrettoken"
    assert "Terminal shell in container" in c["headers"]["Title"]
    assert "rasp" in c["headers"]["Title"]
    assert c["headers"]["Priority"] == "urgent"
    assert c["headers"]["Tags"] == "rotating_light"
    assert "A shell was spawned in a container" in c["data"]


def test_warning_event_does_not_push(client, app_mod, monkeypatch):
    _configure_ntfy(monkeypatch)
    calls = _record_posts(monkeypatch, app_mod)

    r = client.post("/ingest", json={
        "priority": "Warning", "rule": "Sensitive file read",
        "output": "x", "hostname": "blade",
    })
    assert r.status_code == 200
    assert calls == []


def test_notice_event_does_not_push(client, app_mod, monkeypatch):
    _configure_ntfy(monkeypatch)
    calls = _record_posts(monkeypatch, app_mod)

    r = client.post("/ingest", json={
        "priority": "Notice", "rule": "Something noticed",
        "output": "x", "hostname": "blade",
    })
    assert r.status_code == 200
    assert calls == []


def test_unconfigured_ntfy_does_not_push_but_stores(client, app_mod, monkeypatch):
    # NTFY_URL absent -> notifier is a no-op, ingest still works.
    monkeypatch.delenv("NTFY_URL", raising=False)
    calls = _record_posts(monkeypatch, app_mod)

    r = client.post("/ingest", json={
        "priority": "Critical", "rule": "R", "output": "o", "hostname": "rasp",
    })
    assert r.status_code == 200
    assert calls == []
    assert _count_events(app_mod) == 1


def test_ntfy_title_header_is_ascii_safe(client, app_mod, monkeypatch):
    # HTTP header values must be ASCII or httpx raises at send time, silently
    # dropping the alert. Falco rule/host (and our separator) must be sanitized.
    _configure_ntfy(monkeypatch)
    calls = _record_posts(monkeypatch, app_mod)

    r = client.post("/ingest", json={
        "priority": "Critical", "rule": "Café shell — spawned",
        "output": "o", "hostname": "räsp",
    })
    assert r.status_code == 200
    assert len(calls) == 1
    # Must not raise — this is exactly what httpx does to the header internally.
    calls[0]["headers"]["Title"].encode("ascii")


def test_min_priority_env_widens_threshold(client, app_mod, monkeypatch):
    # Default is critical-only, but NTFY_MIN_PRIORITY=warning includes warnings.
    _configure_ntfy(monkeypatch)
    monkeypatch.setenv("NTFY_MIN_PRIORITY", "warning")
    calls = _record_posts(monkeypatch, app_mod)

    r = client.post("/ingest", json={
        "priority": "Warning", "rule": "Sensitive file read",
        "output": "x", "hostname": "blade",
    })
    assert r.status_code == 200
    assert len(calls) == 1


def test_unknown_min_priority_falls_back_to_critical_only(client, app_mod, monkeypatch):
    _configure_ntfy(monkeypatch)
    monkeypatch.setenv("NTFY_MIN_PRIORITY", "bogus")
    calls = _record_posts(monkeypatch, app_mod)

    # warning must NOT push under the safe fallback...
    client.post("/ingest", json={"priority": "Warning", "rule": "r", "output": "x", "hostname": "h"})
    assert calls == []
    # ...but critical still does.
    client.post("/ingest", json={"priority": "Critical", "rule": "r", "output": "x", "hostname": "h"})
    assert len(calls) == 1


def test_ntfy_failure_does_not_break_ingest(client, app_mod, monkeypatch):
    _configure_ntfy(monkeypatch)
    calls = _record_posts(monkeypatch, app_mod, fail=True)

    r = client.post("/ingest", json={
        "priority": "Critical", "rule": "R", "output": "o", "hostname": "rasp",
    })
    # ntfy blew up, but the event must still be accepted and stored.
    assert r.status_code == 200
    assert len(calls) == 1
    assert _count_events(app_mod) == 1


def test_ntfy_non_string_fields_do_not_break_ingest(client, app_mod, monkeypatch):
    # A malformed payload (numeric output/priority) must not crash ingestion:
    # title/body construction is inside notify_ntfy's try, and values are coerced.
    _configure_ntfy(monkeypatch)
    calls = _record_posts(monkeypatch, app_mod)

    r = client.post("/ingest", json={
        "priority": "Critical", "rule": 42, "output": 12345, "hostname": "rasp",
    })
    assert r.status_code == 200
    assert _count_events(app_mod) == 1
    assert len(calls) == 1
    assert "12345" in calls[0]["data"]


def test_ntfy_title_strips_control_chars(client, app_mod, monkeypatch):
    # Newline/CR are ASCII, so encode('ascii','replace') keeps them; httpx then
    # rejects the header and drops the alert. They must be stripped to spaces.
    _configure_ntfy(monkeypatch)
    calls = _record_posts(monkeypatch, app_mod)

    r = client.post("/ingest", json={
        "priority": "Critical", "rule": "line1\nline2\ttab",
        "output": "o", "hostname": "rasp\rx",
    })
    assert r.status_code == 200
    assert len(calls) == 1
    title = calls[0]["headers"]["Title"]
    assert "\n" not in title and "\r" not in title and "\t" not in title
    title.encode("ascii")  # must not raise (what httpx does internally)
