"""falco-triage — a mobile-first triage feed for Falco events.

Receives events from Falcosidekick's webhook output, stores them in SQLite,
and serves a phone-friendly feed (HTMX). One container, no external services.
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
from fastapi.templating import Jinja2Templates

DB_PATH = os.environ.get("DB_PATH", "/data/triage.db")
WEBHOOK_SECRET = os.environ.get("TRIAGE_SECRET", "")
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "30"))
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "15"))

# Falco priority order, most severe first.
CRIT = {"emergency", "alert", "critical", "error"}

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


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
        conn.commit()


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="falco-triage", lifespan=lifespan)


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


def counts(conn: sqlite3.Connection) -> dict:
    total = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    crit = conn.execute(
        "SELECT COUNT(*) c FROM events WHERE LOWER(priority) IN ('emergency','alert','critical','error')"
    ).fetchone()["c"]
    warn = conn.execute(
        "SELECT COUNT(*) c FROM events WHERE LOWER(priority)='warning'"
    ).fetchone()["c"]
    return {"total": total, "critical": crit, "warning": warn}


@app.post("/ingest")
async def ingest(request: Request, x_webhook_secret: str | None = Header(default=None)):
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
def feed(request: Request, priority: str = "", q: str = "", limit: int = 200):
    clauses, params = [], []
    if priority == "critical":
        clauses.append("LOWER(priority) IN ('emergency','alert','critical','error')")
    elif priority == "warning":
        clauses.append("LOWER(priority)='warning'")
    elif priority == "other":
        clauses.append("LOWER(priority) IN ('notice','informational','debug')")
    if q:
        clauses.append("(rule LIKE ? OR output LIKE ? OR hostname LIKE ?)")
        params += [f"%{q}%"] * 3

    sql = "SELECT * FROM events"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY received_at DESC LIMIT ?"
    params.append(limit)

    with closing(db()) as conn:
        rows = conn.execute(sql, params).fetchall()
        ctx_counts = counts(conn)

    return TEMPLATES.TemplateResponse(
        request=request,
        name="_feed.html",
        context={"events": [rowdict(r) for r in rows], "counts": ctx_counts},
    )


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    with closing(db()) as conn:
        ctx_counts = counts(conn)
    return TEMPLATES.TemplateResponse(
        request=request,
        name="index.html",
        context={"counts": ctx_counts, "poll": POLL_SECONDS},
    )


@app.get("/healthz", response_class=PlainTextResponse)
def healthz():
    return "ok"
