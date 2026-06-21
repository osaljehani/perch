# perch

A clean, self-hosted UI for [Falco](https://falco.org) events. Perch ingests
Falco alerts over HTTP, stores them in SQLite, and serves a fast, responsive
feed that works equally well on a phone and a desktop — with filters by
**severity, host, rule, and time**.

One small container, no build step, no external datastore. Built as a friendlier
day-to-day view than the Redis-backed Falcosidekick UI — not a replacement for
it; the two happily run side by side.

## Two ways to connect

Falco's HTTP output and Falcosidekick's webhook output forward the *same* alert
JSON, so perch exposes a single `/ingest` endpoint that serves both paths. Pick
whichever fits your environment:

```
                          ┌─────────────────────────────────────────┐
  Direct path             │                                         │
  Falco ── http_output ───┼──────────────►  perch  /ingest ──► SQLite ──► UI
                          │                  ▲                      │
  Add-on path             │                  │                      │
  Falco ─► Falcosidekick ─┼── webhook ───────┘                      │
            (+ its other outputs, unchanged) └─────────────────────┘
```

- **Direct** — point Falco's `http_output` at perch. No Falcosidekick required.
  See [`deploy/examples/falco-http-output.yaml`](deploy/examples/falco-http-output.yaml).
- **Add-on** — already running Falco + Falcosidekick? Add one webhook output
  pointing at perch; every existing output keeps working (Falcosidekick fans out
  in parallel). See [`deploy/examples/falcosidekick-webhook.yaml`](deploy/examples/falcosidekick-webhook.yaml).

When set, perch checks a shared-secret header (`X-Webhook-Secret`) against
`PERCH_SECRET`. The **add-on path** (Falcosidekick) sends it via the webhook's
custom headers. Falco's **native `http_output` cannot send custom headers**, so
the direct path is either run without a secret on a trusted network/localhost, or
authenticated via `program_output` + `curl -H` — see
[`deploy/examples/falco-http-output.yaml`](deploy/examples/falco-http-output.yaml)
for both.

## Features

- **Responsive UI** — mobile-first, scales up to a roomy desktop layout.
- **Filters** — severity (critical / warning / other), host, rule, and
  time-since (1h / 24h / 7d / all), plus free-text search. All combinable; the
  count badges reflect the current view.
- **Stats** — a Stats tab with pure-CSS charts (events over time, by priority,
  top rules, by host) that respect the active filters. No JS.
- **Export** — download the filtered events as CSV or JSON.
- **Dark + light themes** — dark by default, toggle persists per browser.
- **Expandable cards** — tap an event for its full output, structured fields,
  and tags. Severity shown as a colored stripe.
- **Retention** — events older than `RETENTION_DAYS` are pruned on write.
- **Optional phone alerts** — push critical events to [ntfy](https://ntfy.sh)
  (opt-in; see below).

## Quick start (standalone)

The fastest path is to pull the published multi-arch image (works on amd64 and
arm64 / Raspberry Pi — no build needed):

```sh
export PERCH_SECRET=$(openssl rand -hex 24)
docker run -d -p 8000:8000 \
  -e PERCH_SECRET="$PERCH_SECRET" \
  -v perch-data:/data \
  ghcr.io/osaljehani/perch:v0.1.0
# open http://localhost:8000
```

Send a test event (this is exactly what Falco / Falcosidekick POST):

```sh
curl -XPOST localhost:8000/ingest \
  -H "X-Webhook-Secret: $PERCH_SECRET" \
  -H "Content-Type: application/json" \
  -d @deploy/sample-event.json
```

Then wire up Falco or Falcosidekick using the snippets in
[`deploy/examples/`](deploy/examples/).

### Build it yourself

Prefer to build from source (e.g. you forked perch)? The compose file builds the
local `app/` directory natively for your architecture:

```sh
export PERCH_SECRET=$(openssl rand -hex 24)
docker compose -f deploy/docker-compose.yaml up --build
```

### Releases

Images are published to GHCR by a tag-driven workflow: pushing a `v*` tag builds
and pushes `ghcr.io/osaljehani/perch:<tag>` plus `:latest`. **Pin a version** (as
the examples above do) rather than tracking `:latest`, so an existing setup keeps
working across releases.

## Run from source

```sh
cd app
pip install -r requirements.txt
PERCH_SECRET=test uvicorn main:app --port 8000
```

## Optional: phone alerts via ntfy

Perch can push **critical** Falco events to your phone through
[ntfy](https://ntfy.sh). It's **opt-in and safe**: disabled unless `NTFY_URL` is
set, and any publish failure is logged and **never blocks ingestion** — a down
ntfy can't drop events. The default threshold is critical-tier only
(`emergency`/`alert`/`critical`/`error`); widen it to `warning` with one env var,
no rebuild.

Two ways to wire it up:

1. **Public/hosted ntfy** — simplest. Set `NTFY_URL=https://ntfy.sh` and a
   hard-to-guess topic (`NTFY_TOPIC`), then subscribe to that topic in the ntfy
   app. No token needed for public topics.
2. **Self-hosted ntfy** — point `NTFY_URL` at your own server (e.g. behind a
   Cloudflare tunnel: `NTFY_URL=https://ntfy.example.com`) and set `NTFY_TOKEN`
   if it requires auth. Your phone subscribes to the same topic.

Smoke-test the server→phone path without perch in the loop:

```sh
curl -H "Authorization: Bearer <tk_...>" -H "Title: test" \
     -H "Priority: urgent" -H "Tags: rotating_light" \
     -d "hello" https://ntfy.example.com/falco-alerts   # 200, phone buzzes
```

See the `NTFY_*` rows in [Configuration](#configuration) for all options.

## Kubernetes

Generic manifests live in [`deploy/kubernetes/`](deploy/kubernetes/):

```sh
# set a real token in deploy/kubernetes/secret.example.yaml first
kubectl apply -k deploy/kubernetes
```

A Flux/SOPS example for GitOps homelabs is in
[`deploy/examples/flux/`](deploy/examples/flux/).

## Configuration

| Env var          | Default          | Meaning                                            |
|------------------|------------------|----------------------------------------------------|
| `PERCH_SECRET`   | (none)           | Shared token; must match the `X-Webhook-Secret` header. Empty disables auth (local testing only). |
| `DB_PATH`        | `/data/perch.db` | SQLite path.                                       |
| `POLL_SECONDS`   | `15`             | Feed auto-refresh interval.                        |
| `RETENTION_DAYS` | `30`             | Events older than this are pruned on write.        |
| `NTFY_URL`       | (none)           | ntfy base URL. **Unset = phone alerts disabled.**  |
| `NTFY_TOPIC`     | `falco-alerts`   | ntfy topic to publish to.                          |
| `NTFY_MIN_PRIORITY` | `error`       | Minimum severity to push. `error` = critical-tier; set to `warning` to include warnings. |
| `NTFY_TOKEN`     | (none)           | Bearer token, for ntfy servers that require auth.  |

`TRIAGE_SECRET` is still read as a fallback for older deployments.

## Project layout

```
app/                 FastAPI + HTMX application (the container source)
  main.py            ingest + feed + filters + stats + export + ntfy
  templates/         index + HTMX partials (feed, stats, counts)
  static/            design-system CSS + theme toggle
  tests/             pytest suite (ntfy + stats/export); not shipped in the image
deploy/
  docker-compose.yaml
  kubernetes/        generic manifests (kustomize)
  examples/          Falco http_output / Falcosidekick webhook / Flux snippets
  sample-event.json
```
