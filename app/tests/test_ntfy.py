"""Tests for the optional ntfy critical-alert notifier wired into POST /ingest.

The raw HTTP POST is isolated in ``main.post_ntfy`` so these tests monkeypatch
it and never hit the network.
"""
import asyncio
import logging
from contextlib import closing

import httpx


class _FakeClient:
    """Stand-in for httpx.AsyncClient returning a canned response (no network)."""

    def __init__(self, status: int, body: str = ""):
        self._status = status
        self._body = body

    def __call__(self, *args, **kwargs):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, headers=None, content=None):
        return httpx.Response(self._status, text=self._body,
                              request=httpx.Request("POST", url))


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
        return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr(app_mod, "post_ntfy", fake_post)
    return calls


def _scripted_posts(monkeypatch, app_mod, outcomes):
    """Fake post_ntfy that walks `outcomes`: an int is a status code, an exception is raised."""
    calls = []

    async def fake_post(url, headers, data):
        outcome = outcomes[min(len(calls), len(outcomes) - 1)]
        calls.append(url)
        if isinstance(outcome, Exception):
            raise outcome
        return httpx.Response(outcome, text="body", request=httpx.Request("POST", url))

    monkeypatch.setattr(app_mod, "post_ntfy", fake_post)
    return calls


def _no_sleep(monkeypatch, app_mod):
    """Record retry backoff delays instead of actually sleeping."""
    slept = []

    async def fake_sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr(app_mod.asyncio, "sleep", fake_sleep)
    return slept


def _publish(app_mod):
    asyncio.run(app_mod.publish_ntfy("https://ntfy.example.com/falco-alerts", {}, "body"))


_DNS_ERROR = httpx.ConnectError("[Errno -5] No address associated with hostname")


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
        "hostname": "node-01",
    })
    assert r.status_code == 200
    assert len(calls) == 1
    c = calls[0]
    assert c["url"] == "https://ntfy.example.com/falco-alerts"
    assert c["headers"]["Authorization"] == "Bearer tk_secrettoken"
    assert "Terminal shell in container" in c["headers"]["Title"]
    assert "node-01" in c["headers"]["Title"]
    assert c["headers"]["Priority"] == "urgent"
    assert c["headers"]["Tags"] == "rotating_light"
    assert "A shell was spawned in a container" in c["data"]


def test_warning_event_does_not_push(client, app_mod, monkeypatch):
    _configure_ntfy(monkeypatch)
    calls = _record_posts(monkeypatch, app_mod)

    r = client.post("/ingest", json={
        "priority": "Warning", "rule": "Sensitive file read",
        "output": "x", "hostname": "node-02",
    })
    assert r.status_code == 200
    assert calls == []


def test_notice_event_does_not_push(client, app_mod, monkeypatch):
    _configure_ntfy(monkeypatch)
    calls = _record_posts(monkeypatch, app_mod)

    r = client.post("/ingest", json={
        "priority": "Notice", "rule": "Something noticed",
        "output": "x", "hostname": "node-02",
    })
    assert r.status_code == 200
    assert calls == []


def test_unconfigured_ntfy_does_not_push_but_stores(client, app_mod, monkeypatch):
    # NTFY_URL absent -> notifier is a no-op, ingest still works.
    monkeypatch.delenv("NTFY_URL", raising=False)
    calls = _record_posts(monkeypatch, app_mod)

    r = client.post("/ingest", json={
        "priority": "Critical", "rule": "R", "output": "o", "hostname": "node-01",
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
        "output": "x", "hostname": "node-02",
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
        "priority": "Critical", "rule": "R", "output": "o", "hostname": "node-01",
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
        "priority": "Critical", "rule": 42, "output": 12345, "hostname": "node-01",
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
        "output": "o", "hostname": "node-01\rx",
    })
    assert r.status_code == 200
    assert len(calls) == 1
    title = calls[0]["headers"]["Title"]
    assert "\n" not in title and "\r" not in title and "\t" not in title
    title.encode("ascii")  # must not raise (what httpx does internally)


def test_publish_logs_status_on_non_2xx(app_mod, monkeypatch, caplog):
    # httpx never raises on a non-2xx, so an ntfy rejection (auth/ACL) would be
    # dropped silently. The status code + body must surface in the log.
    monkeypatch.setattr(app_mod.httpx, "AsyncClient",
                        _FakeClient(403, '{"error":"forbidden"}'))
    with caplog.at_level(logging.WARNING, logger="perch"):
        _publish(app_mod)
    assert any("403" in r.message and "forbidden" in r.message for r in caplog.records)


def test_publish_silent_on_success(app_mod, monkeypatch, caplog):
    monkeypatch.setattr(app_mod.httpx, "AsyncClient", _FakeClient(200, ""))
    with caplog.at_level(logging.WARNING, logger="perch"):
        _publish(app_mod)
    assert caplog.records == []


def test_transient_dns_failure_is_retried_then_delivered(app_mod, monkeypatch, caplog):
    # A momentary DNS blip must not drop the alert: transport errors are retried.
    calls = _scripted_posts(monkeypatch, app_mod, [_DNS_ERROR, _DNS_ERROR, 200])
    slept = _no_sleep(monkeypatch, app_mod)
    with caplog.at_level(logging.WARNING, logger="perch"):
        _publish(app_mod)
    assert len(calls) == 3
    assert slept == list(app_mod.NTFY_RETRY_DELAYS[:2])
    assert caplog.records == []  # delivered in the end -> nothing to warn about


def test_persistent_failure_gives_up_and_logs(app_mod, monkeypatch, caplog):
    calls = _scripted_posts(monkeypatch, app_mod, [_DNS_ERROR])
    slept = _no_sleep(monkeypatch, app_mod)
    with caplog.at_level(logging.WARNING, logger="perch"):
        _publish(app_mod)
    assert len(calls) == len(app_mod.NTFY_RETRY_DELAYS) + 1
    assert slept == list(app_mod.NTFY_RETRY_DELAYS)
    assert any("No address" in r.message for r in caplog.records)


def test_server_error_and_rate_limit_are_retried(app_mod, monkeypatch):
    calls = _scripted_posts(monkeypatch, app_mod, [502, 429, 200])
    _no_sleep(monkeypatch, app_mod)
    _publish(app_mod)
    assert len(calls) == 3


def test_client_error_is_not_retried(app_mod, monkeypatch, caplog):
    # A 401/403 is a token/ACL problem; retrying cannot fix it.
    calls = _scripted_posts(monkeypatch, app_mod, [403])
    slept = _no_sleep(monkeypatch, app_mod)
    with caplog.at_level(logging.WARNING, logger="perch"):
        _publish(app_mod)
    assert len(calls) == 1
    assert slept == []
    assert any("403" in r.message for r in caplog.records)


def test_ingest_retries_ntfy_after_responding(client, app_mod, monkeypatch):
    # The push (with its retries) runs as a background task, so the event is
    # stored and acknowledged even while ntfy is unreachable.
    _configure_ntfy(monkeypatch)
    calls = _scripted_posts(monkeypatch, app_mod, [_DNS_ERROR, 200])
    _no_sleep(monkeypatch, app_mod)
    r = client.post("/ingest", json={
        "priority": "Critical", "rule": "R", "output": "o", "hostname": "node-01",
    })
    assert r.status_code == 200
    assert _count_events(app_mod) == 1
    assert len(calls) == 2
