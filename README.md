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

Both paths send a shared-secret header (`X-Webhook-Secret`) that must match
perch's `PERCH_SECRET`.

## Features

- **Responsive UI** — mobile-first, scales up to a roomy desktop layout.
- **Filters** — severity (critical / warning / other), host, rule, and
  time-since (1h / 24h / 7d / all), plus free-text search. All combinable; the
  count badges reflect the current view.
- **Dark + light themes** — dark by default, toggle persists per browser.
- **Expandable cards** — tap an event for its full output, structured fields,
  and tags. Severity shown as a colored stripe.
- **Retention** — events older than `RETENTION_DAYS` are pruned on write.

## Quick start (standalone)

```sh
export PERCH_SECRET=$(openssl rand -hex 24)
docker compose -f deploy/docker-compose.yaml up --build
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

## Run from source

```sh
cd app
pip install -r requirements.txt
PERCH_SECRET=test uvicorn main:app --port 8000
```

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

`TRIAGE_SECRET` is still read as a fallback for older deployments.

## Project layout

```
app/                 FastAPI + HTMX application (the container source)
  main.py            ingest + feed + filters
  templates/         index + HTMX partials
  static/            design-system CSS + theme toggle
deploy/
  docker-compose.yaml
  kubernetes/        generic manifests (kustomize)
  examples/          Falco http_output / Falcosidekick webhook / Flux snippets
  sample-event.json
```
