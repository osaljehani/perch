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
import hmac
import json
import os
import sqlite3
from contextlib import asynccontextmanager, closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

DB_PATH = os.environ.get("DB_PATH", "/data/perch.db")
# PERCH_SECRET is preferred; TRIAGE_SECRET kept as a fallback for older deploys.
WEBHOOK_SECRET = os.environ.get("PERCH_SECRET") or os.environ.get("TRIAGE_SECRET", "")
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "30"))
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "15"))

BASE_DIR = Path(__file__).parent

# Falco priority order, most severe first. These map to the "critical" group.
CRIT = {"emergency", "alert", "critical", "error"}

# Time-since windows offered by the UI -> timedelta.
SINCE_WINDOWS = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}

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
        clauses.append("(rule LIKE ? OR output LIKE ? OR hostname LIKE ?)")
        params += [f"%{q}%"] * 3
    return clauses, params


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


@app.post("/ingest")
async def ingest(request: Request, x_webhook_secret: str | None = Header(default=None)):
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
    return JSONResponse({"status": "ok"})


@app.get("/feed", response_class=HTMLResponse)
def feed(
    request: Request,
    priority: str = "",
    host: str = "",
    rule: str = "",
    since: str = "",
    q: str = "",
    limit: int = 200,
):
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

    sql = "SELECT * FROM events"
    if clauses:
        sql += " WHERE " + " AND ".join(f"({c})" for c in clauses)
    sql += " ORDER BY received_at DESC LIMIT ?"
    params.append(limit)

    # Count badges reflect the scope (host/time/search), not the severity chip.
    scope, scope_params = scope_clauses(host, since, q)
    scope_sql = (" WHERE " + " AND ".join(f"({c})" for c in scope)) if scope else ""

    with closing(db()) as conn:
        rows = conn.execute(sql, params).fetchall()
        ctx_counts = counts(conn, scope_sql, scope_params)

    return TEMPLATES.TemplateResponse(
        request=request,
        name="_feed.html",
        context={"events": [rowdict(r) for r in rows], "counts": ctx_counts},
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
