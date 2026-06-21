"""perch — a clean, self-hosted UI for Falco events.

Perch ingests Falco alerts over HTTP, stores them in SQLite, and serves a
responsive feed (HTMX, no build step, one container). It supports two
integration paths that POST the *identical* Falco alert JSON to ``/ingest``:

  1. Direct      — Falco's own ``http_output`` points at perch.
  2. Add-on      — Falcosidekick's ``webhook`` output points at perch
                   (drop-in for environments already running Falcosidekick).

Because Falco's HTTP output and Falcosidekick's webhook output forward the same
payload, a single endpoint, store, and UI serve both paths.
"""
import csv
import hmac
import io
import json
import logging
import os
import sqlite3
from contextlib import asynccontextmanager, closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

import httpx
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

DB_PATH = os.environ.get("DB_PATH", "/data/perch.db")
# PERCH_SECRET is preferred; TRIAGE_SECRET kept as a fallback for older deploys.
WEBHOOK_SECRET = os.environ.get("PERCH_SECRET") or os.environ.get("TRIAGE_SECRET", "")
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "30"))
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "15"))

log = logging.getLogger("perch")

BASE_DIR = Path(__file__).parent

# Falco priority order, most severe first. The first four map to "critical".
PRIORITY_ORDER = ["emergency", "alert", "critical", "error",
                  "warning", "notice", "informational", "debug"]
CRIT = {"emergency", "alert", "critical", "error"}


def priorities_at_or_above(min_priority: str) -> set:
    """Priorities at least as severe as `min_priority`. Unknown -> CRIT (safe default)."""
    p = (min_priority or "").lower()
    if p in PRIORITY_ORDER:
        return set(PRIORITY_ORDER[: PRIORITY_ORDER.index(p) + 1])
    return set(CRIT)


# Time-since windows offered by the UI -> timedelta.
SINCE_WINDOWS = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}

# (num_buckets, minutes_per_bucket) for the stats "over time" histogram, keyed to
# SINCE_WINDOWS. When the window is "All" (no key), fall back to a 24h view.
BUCKET_SPEC = {
    "1h": (12, 5),
    "6h": (18, 20),
    "24h": (24, 60),
    "7d": (28, 360),
    "30d": (30, 1440),
}

# Columns emitted by CSV/JSON export, in order.
EXPORT_COLUMNS = ["received_at", "event_time", "rule", "priority", "source",
                  "hostname", "output", "tags", "fields"]

# Cycling palette for the "by host" donut (hosts have no fixed color).
CHART_COLORS = [f"chart-{n}" for n in range(1, 7)]


def export_qs(priority: str, q: str, since: str, host: str, rule: str) -> str:
    """Filter state as a query string, so export links track the active view."""
    return urlencode({"priority": priority, "q": q, "since": since,
                      "host": host, "rule": rule})


def _csv_safe(value):
    """Guard against CSV formula injection: a cell beginning with =, +, -, @, or a
    leading tab/CR is evaluated as a formula by Excel/Sheets. Falco output is
    attacker-influenceable, so prefix such values with a single quote.
    """
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value

TEMPLATES = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with closing(db()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TEXT NOT NULL,
                event_time  TEXT,
                rule        TEXT,
                priority    TEXT,
                source      TEXT,
                hostname    TEXT,
                output      TEXT,
                tags        TEXT,
                fields      TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_recv ON events(received_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_prio ON events(priority)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_host ON events(hostname)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rule ON events(rule)")
        conn.commit()


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="perch", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


def humanize(iso: str | None) -> str:
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return iso
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    s = int((datetime.now(timezone.utc) - dt).total_seconds())
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h"
    return f"{s // 86400}d"


def pclass(priority: str | None) -> str:
    p = (priority or "").lower()
    if p in CRIT:
        return "crit"
    if p == "warning":
        return "warn"
    if p == "notice":
        return "notice"
    if p == "debug":
        return "debug"
    return "info"


def rowdict(r: sqlite3.Row) -> dict:
    return {
        "rule": r["rule"] or "—",
        "priority": (r["priority"] or "").lower(),
        "pclass": pclass(r["priority"]),
        "source": r["source"] or "",
        "hostname": r["hostname"] or "",
        "output": r["output"] or "",
        "fields": json.loads(r["fields"] or "{}"),
        "tags": json.loads(r["tags"] or "[]"),
        "rel": humanize(r["received_at"]),
        "event_time": r["event_time"] or "",
    }


def scope_clauses(host: str, since: str, q: str) -> tuple[list[str], list]:
    """Filters that define the visible 'scope' (everything except severity).

    Shared by the feed query and the count badges so the badges reflect the
    current view rather than the whole database.
    """
    clauses: list[str] = []
    params: list = []
    if host:
        clauses.append("hostname = ?")
        params.append(host)
    if since in SINCE_WINDOWS:
        cutoff = (datetime.now(timezone.utc) - SINCE_WINDOWS[since]).isoformat()
        clauses.append("received_at >= ?")
        params.append(cutoff)
    if q:
        # Escape LIKE wildcards so a literal % or _ in the search isn't treated
        # as a wildcard (would over-match the feed, stats, and export).
        esc = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append(
            "(rule LIKE ? ESCAPE '\\' OR output LIKE ? ESCAPE '\\' "
            "OR hostname LIKE ? ESCAPE '\\')"
        )
        params += [f"%{esc}%"] * 3
    return clauses, params


def where_sql(clauses: list[str]) -> str:
    """Render clause list as a SQL WHERE fragment (empty string if no clauses)."""
    return (" WHERE " + " AND ".join(f"({c})" for c in clauses)) if clauses else ""


def filter_clauses(priority: str, host: str, rule: str, since: str, q: str):
    """Full filter (scope + rule + severity), shared by feed, stats, and export."""
    clauses, params = scope_clauses(host, since, q)
    if rule:
        clauses.append("rule = ?")
        params.append(rule)
    if priority == "critical":
        clauses.append("LOWER(priority) IN ('emergency','alert','critical','error')")
    elif priority == "warning":
        clauses.append("LOWER(priority)='warning'")
    elif priority == "other":
        clauses.append("LOWER(priority) IN ('notice','informational','debug') OR priority IS NULL")
    return clauses, params


def bucketize(timestamps, since: str, now: datetime):
    """Bucket received_at timestamps into a histogram for the over-time chart.

    For a fixed window (since in BUCKET_SPEC) the span is now-window..now. For
    the 'All' window (anything else) the span runs oldest-event..now so events
    are never silently dropped — otherwise the chart would read all-zero while
    the count badges show a non-zero total.
    """
    parsed = []
    for ts in timestamps:
        try:
            dt = datetime.fromisoformat(ts)
        except (TypeError, ValueError):
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        parsed.append(dt)

    if since in BUCKET_SPEC:
        n, width_min = BUCKET_SPEC[since]
        width = timedelta(minutes=width_min)
        wide = since in ("7d", "30d")
    else:
        # 'All' — span the actual data range so old events still show.
        n = 30
        oldest = min(parsed) if parsed else now - timedelta(hours=24)
        span = max(now - oldest, timedelta(minutes=n))
        width = span / n
        wide = span >= timedelta(days=2)

    start = now - width * n
    buckets = [0] * n
    for dt in parsed:
        idx = int((dt - start) / width)
        if idx == n:          # the right edge (== now) belongs to the last bucket
            idx = n - 1
        if 0 <= idx < n:
            buckets[idx] += 1
    fmt = "%m-%d" if wide else "%H:%M"
    return [
        {"label": (start + width * i).strftime(fmt), "count": c}
        for i, c in enumerate(buckets)
    ]


def donut_segments(items):
    """Turn [{'label','count','color'}, ...] into conic-gradient pie slices.

    Each slice carries cumulative `start`/`end` percents (for the CSS
    conic-gradient) plus its own `pct`. Returns [] when the total is 0 so the
    template can fall back to an empty state.
    """
    total = sum(i["count"] for i in items)
    if not total:
        return []
    segs, acc = [], 0
    for i in items:
        start = acc / total * 100
        acc += i["count"]
        end = acc / total * 100
        segs.append({**i, "start": round(start, 2), "end": round(end, 2),
                     "pct": round(i["count"] / total * 100)})
    return segs


def counts(conn: sqlite3.Connection, scope_sql: str, scope_params: list) -> dict:
    base = f"SELECT COUNT(*) c FROM events{scope_sql}"

    def with_extra(extra: str) -> int:
        sql = base + (" AND " if scope_sql else " WHERE ") + extra
        return conn.execute(sql, scope_params).fetchone()["c"]

    total = conn.execute(base, scope_params).fetchone()["c"]
    crit = with_extra(
        "LOWER(priority) IN ('emergency','alert','critical','error')"
    )
    warn = with_extra("LOWER(priority)='warning'")
    other = with_extra(
        "LOWER(priority) IN ('notice','informational','debug') OR priority IS NULL"
    )
    return {"total": total, "critical": crit, "warning": warn, "other": other}


def distinct(conn: sqlite3.Connection, column: str) -> list[str]:
    """Sorted distinct non-empty values for a column, for filter dropdowns."""
    if column not in {"hostname", "rule"}:  # guard against injection
        return []
    rows = conn.execute(
        f"SELECT DISTINCT {column} v FROM events "
        f"WHERE {column} IS NOT NULL AND {column} != '' ORDER BY {column}"
    ).fetchall()
    return [r["v"] for r in rows]


async def post_ntfy(url: str, headers: dict, data: str) -> None:
    """Raw ntfy publish — isolated so tests can monkeypatch it (no network)."""
    async with httpx.AsyncClient(timeout=5) as c:
        await c.post(url, headers=headers, content=data.encode("utf-8"))


def _ascii_header(value: str) -> str:
    """Make a string safe as an HTTP header value.

    httpx rejects non-ASCII *and* control characters (newline/CR/tab) and raises
    at send time, which would silently drop the alert. Control chars become
    spaces and non-ASCII is replaced. Lossy is fine — the UTF-8 body keeps the
    full detail.
    """
    cleaned = "".join(c if " " <= c < "\x7f" else " " for c in value)
    return cleaned.encode("ascii", "replace").decode("ascii")


async def notify_ntfy(payload: dict, hostname: str = "") -> None:
    """Push a phone alert for critical Falco events. Opt-in via NTFY_URL.

    Disabled unless NTFY_URL is set. A failure here must never break ingestion,
    so everything — including title/body construction — is swallowed and logged.
    """
    base = os.environ.get("NTFY_URL", "").rstrip("/")
    if not base:
        return
    allowed = priorities_at_or_above(os.environ.get("NTFY_MIN_PRIORITY", "error"))
    if str(payload.get("priority") or "").lower() not in allowed:
        return
    try:
        topic = os.environ.get("NTFY_TOPIC", "falco-alerts")
        token = os.environ.get("NTFY_TOKEN", "")
        # Coerce to str: a malformed payload (non-string rule/output) must not
        # crash ingestion.
        rule = str(payload.get("rule") or "Falco alert")
        host = str(hostname or "")
        title = _ascii_header(f"{rule} - {host}" if host else rule)
        body = str(payload.get("output") or rule)[:400]
        headers = {"Title": title, "Priority": "urgent", "Tags": "rotating_light"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        await post_ntfy(f"{base}/{topic}", headers, body)
    except Exception as e:
        log.warning("ntfy publish failed: %s", e)


@app.post("/ingest")
async def ingest(request: Request, background_tasks: BackgroundTasks,
                 x_webhook_secret: str | None = Header(default=None)):
    # Both integration paths (Falco http_output, Falcosidekick webhook) POST the
    # same Falco alert JSON here.
    if WEBHOOK_SECRET:
        if not x_webhook_secret or not hmac.compare_digest(x_webhook_secret, WEBHOOK_SECRET):
            raise HTTPException(status_code=401, detail="unauthorized")
    try:
        p = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json")

    fields = p.get("output_fields") or {}
    hostname = (
        p.get("hostname")
        or fields.get("hostname")
        or fields.get("container.name")
        or ""
    )
    with closing(db()) as conn:
        conn.execute(
            "INSERT INTO events (received_at, event_time, rule, priority, source, hostname, output, tags, fields)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (
                datetime.now(timezone.utc).isoformat(),
                p.get("time"),
                p.get("rule"),
                p.get("priority"),
                p.get("source"),
                hostname,
                p.get("output"),
                json.dumps(p.get("tags") or []),
                json.dumps(fields),
            ),
        )
        cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat()
        conn.execute("DELETE FROM events WHERE received_at < ?", (cutoff,))
        conn.commit()
    # Fire the (opt-in) ntfy alert after the response is sent, so a slow or down
    # ntfy never delays/blocks ingestion.
    background_tasks.add_task(notify_ntfy, p, hostname)
    return JSONResponse({"status": "ok"})


def render_feed(request, *, priority, host, rule, since, q, limit):
    clauses, params = filter_clauses(priority, host, rule, since, q)
    sql = f"SELECT * FROM events{where_sql(clauses)} ORDER BY received_at DESC LIMIT ?"

    # Count badges reflect the scope (host/time/search), not the severity chip.
    scope, scope_params = scope_clauses(host, since, q)
    with closing(db()) as conn:
        rows = conn.execute(sql, params + [limit]).fetchall()
        ctx_counts = counts(conn, where_sql(scope), scope_params)

    return TEMPLATES.TemplateResponse(
        request=request,
        name="_feed.html",
        context={
            "events": [rowdict(r) for r in rows],
            "counts": ctx_counts,
            "qs": export_qs(priority, q, since, host, rule),
        },
    )


def render_stats(request, *, priority, host, rule, since, q):
    clauses, params = filter_clauses(priority, host, rule, since, q)
    where = where_sql(clauses)
    scope, scope_params = scope_clauses(host, since, q)
    with closing(db()) as conn:
        recv = [r["received_at"] for r in
                conn.execute(f"SELECT received_at FROM events{where}", params).fetchall()]
        prio_rows = conn.execute(f"SELECT priority FROM events{where}", params).fetchall()
        rule_rows = conn.execute(
            f"SELECT rule, COUNT(*) c FROM events{where} GROUP BY rule ORDER BY c DESC LIMIT 8",
            params).fetchall()
        # Cap to the palette size: more hosts than colors makes the donut
        # unreadable (repeated colors, oversized legend). Top-N, like top rules.
        host_rows = conn.execute(
            f"SELECT hostname, COUNT(*) c FROM events{where} GROUP BY hostname "
            f"ORDER BY c DESC LIMIT {len(CHART_COLORS)}",
            params).fetchall()
        ctx_counts = counts(conn, where_sql(scope), scope_params)

    by_priority = {"crit": 0, "warn": 0, "other": 0}
    for r in prio_rows:
        cls = pclass(r["priority"])
        by_priority["crit" if cls == "crit" else "warn" if cls == "warn" else "other"] += 1

    over_time = bucketize(recv, since, datetime.now(timezone.utc))
    top_rules = [{"rule": r["rule"] or "—", "count": r["c"]} for r in rule_rows]
    by_host = [{"hostname": r["hostname"] or "unknown", "count": r["c"]} for r in host_rows]

    priority_segments = donut_segments([
        {"label": "crit", "count": by_priority["crit"], "color": "sev-crit"},
        {"label": "warn", "count": by_priority["warn"], "color": "sev-warn"},
        {"label": "other", "count": by_priority["other"], "color": "sev-info"},
    ])
    host_segments = donut_segments([
        {"label": h["hostname"], "count": h["count"],
         "color": CHART_COLORS[i % len(CHART_COLORS)]}
        for i, h in enumerate(by_host)
    ])
    return TEMPLATES.TemplateResponse(
        request=request,
        name="_stats.html",
        context={
            "over_time": over_time,
            "over_time_max": max([b["count"] for b in over_time] + [1]),
            "by_priority": by_priority,
            "priority_segments": priority_segments,
            "top_rules": top_rules,
            "top_rules_max": max([x["count"] for x in top_rules] + [1]),
            "host_segments": host_segments,
            "counts": ctx_counts,
            "since": since or "all",
            "qs": export_qs(priority, q, since, host, rule),
        },
    )


@app.get("/feed", response_class=HTMLResponse)
def feed(request: Request, priority: str = "", host: str = "", rule: str = "",
         since: str = "", q: str = "", limit: int = 200):
    return render_feed(request, priority=priority, host=host, rule=rule,
                       since=since, q=q, limit=limit)


@app.get("/stats", response_class=HTMLResponse)
def stats(request: Request, priority: str = "", host: str = "", rule: str = "",
          since: str = "", q: str = ""):
    return render_stats(request, priority=priority, host=host, rule=rule,
                        since=since, q=q)


@app.get("/view", response_class=HTMLResponse)
def view(request: Request, view: str = "feed", priority: str = "", host: str = "",
         rule: str = "", since: str = "", q: str = "", limit: int = 200):
    if view == "stats":
        return render_stats(request, priority=priority, host=host, rule=rule,
                            since=since, q=q)
    return render_feed(request, priority=priority, host=host, rule=rule,
                       since=since, q=q, limit=limit)


@app.get("/export")
def export(fmt: str = "csv", priority: str = "", q: str = "", since: str = "",
           host: str = "", rule: str = ""):
    clauses, params = filter_clauses(priority, host, rule, since, q)
    sql = f"SELECT {', '.join(EXPORT_COLUMNS)} FROM events{where_sql(clauses)} ORDER BY received_at DESC"
    with closing(db()) as conn:
        rows = conn.execute(sql, params).fetchall()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    if fmt == "json":
        data = []
        for r in rows:
            d = {k: r[k] for k in EXPORT_COLUMNS}
            d["tags"] = json.loads(r["tags"] or "[]")
            d["fields"] = json.loads(r["fields"] or "{}")
            data.append(d)
        return JSONResponse(
            data,
            headers={"Content-Disposition": f'attachment; filename="perch-events-{stamp}.json"'},
        )
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(EXPORT_COLUMNS)
    for r in rows:
        w.writerow([_csv_safe(r[k]) for k in EXPORT_COLUMNS])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="perch-events-{stamp}.csv"'},
    )


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    with closing(db()) as conn:
        ctx_counts = counts(conn, "", [])
        hosts = distinct(conn, "hostname")
        rules = distinct(conn, "rule")
    return TEMPLATES.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "counts": ctx_counts,
            "hosts": hosts,
            "rules": rules,
            "poll": POLL_SECONDS,
        },
    )


@app.get("/healthz", response_class=PlainTextResponse)
def healthz():
    return "ok"
