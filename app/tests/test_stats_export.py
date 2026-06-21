"""Tests for the stats view (/stats, /view?view=stats) and CSV/JSON export."""
import csv
import io
import re
from datetime import datetime, timedelta, timezone

COLS = ["received_at", "event_time", "rule", "priority", "source",
        "hostname", "output", "tags", "fields"]


def _ingest(client, **over):
    payload = {"priority": "Warning", "rule": "R", "output": "out", "hostname": "h1"}
    payload.update(over)
    r = client.post("/ingest", json=payload)
    assert r.status_code == 200


def test_stats_renders_with_events(client):
    _ingest(client, priority="Critical", rule="Shell", hostname="node-01")
    _ingest(client, priority="Warning", rule="File read", hostname="node-02")
    r = client.get("/stats")
    assert r.status_code == 200
    body = r.text
    assert "Events over time" in body
    assert "By priority" in body
    assert "Top rules" in body
    assert "By host" in body
    # OOB swaps for the count badges and export links are present.
    assert 'id="counts"' in body
    assert "/export?fmt=csv" in body


def test_view_dispatches_to_stats(client):
    _ingest(client, priority="Critical", rule="Shell")
    r = client.get("/view", params={"view": "stats"})
    assert r.status_code == 200
    assert "Events over time" in r.text


def test_view_defaults_to_feed(client):
    _ingest(client, priority="Critical", rule="Shell")
    r = client.get("/view")
    assert r.status_code == 200
    assert "Events over time" not in r.text  # feed partial, not stats


def test_export_csv(client):
    _ingest(client, priority="Critical", rule="Shell", hostname="node-01")
    _ingest(client, priority="Warning", rule="File read", hostname="node-02")
    r = client.get("/export", params={"fmt": "csv"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    assert ".csv" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0] == ["received_at", "event_time", "rule", "priority", "source",
                       "hostname", "output", "tags", "fields"]
    assert len(rows) == 3  # header + 2 events


def test_export_json(client):
    _ingest(client, priority="Critical", rule="Shell", hostname="node-01", output="A shell")
    r = client.get("/export", params={"fmt": "json"})
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    assert r.headers["content-disposition"].endswith('.json"')
    data = r.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["rule"] == "Shell"
    # tags/fields are re-parsed back into native JSON, not left as strings.
    assert isinstance(data[0]["tags"], list)
    assert isinstance(data[0]["fields"], dict)


def test_export_respects_priority_filter(client):
    _ingest(client, priority="Critical", rule="Shell")
    _ingest(client, priority="Warning", rule="File read")
    r = client.get("/export", params={"fmt": "csv", "priority": "critical"})
    rows = list(csv.reader(io.StringIO(r.text)))
    assert len(rows) == 2  # header + 1 critical


def test_csv_export_neutralizes_formula_injection(client):
    _ingest(client, rule="=cmd()", output="+SUM(A1)", hostname="@evil", priority="warning")
    r = client.get("/export", params={"fmt": "csv"})
    row = list(csv.reader(io.StringIO(r.text)))[1]
    assert row[COLS.index("rule")].startswith("'=")
    assert row[COLS.index("output")].startswith("'+")
    assert row[COLS.index("hostname")].startswith("'@")


def test_search_escapes_like_underscore(client):
    # '_' is a SQL LIKE single-char wildcard; the search must treat it literally.
    _ingest(client, rule="a_b")
    _ingest(client, rule="axb")
    r = client.get("/export", params={"fmt": "csv", "q": "a_b"})
    rows = list(csv.reader(io.StringIO(r.text)))
    assert len(rows) == 2  # header + only the literal "a_b" (not "axb")


def test_stats_all_window_includes_old_events(client, insert):
    # Default 'since' is All; the over-time chart must span old events, not a
    # fixed 24h window that silently drops them.
    insert(datetime.now(timezone.utc) - timedelta(days=10),
           rule="Old", priority="critical", hostname="h")
    r = client.get("/stats")
    assert r.status_code == 200
    # at least one spark bar carries a non-zero count (title="<label>: <n>").
    assert re.search(r'title="[^"]*: [1-9]', r.text)
