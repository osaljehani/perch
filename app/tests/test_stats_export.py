"""Tests for the stats view (/stats, /view?view=stats) and CSV/JSON export."""
import csv
import io


def _ingest(client, **over):
    payload = {"priority": "Warning", "rule": "R", "output": "out", "hostname": "h1"}
    payload.update(over)
    r = client.post("/ingest", json=payload)
    assert r.status_code == 200


def test_stats_renders_with_events(client):
    _ingest(client, priority="Critical", rule="Shell", hostname="rasp")
    _ingest(client, priority="Warning", rule="File read", hostname="blade")
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
    _ingest(client, priority="Critical", rule="Shell", hostname="rasp")
    _ingest(client, priority="Warning", rule="File read", hostname="blade")
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
    _ingest(client, priority="Critical", rule="Shell", hostname="rasp", output="A shell")
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
