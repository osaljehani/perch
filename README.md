# falco-triage

A mobile-first triage feed for Falco events. Falcosidekick's webhook output POSTs
each event to this app; it stores them in SQLite and serves a phone-friendly feed
(HTMX, no build step, one container). Built to replace day-to-day use of
falcosidekick-ui on a phone — not to replace its Redis store, which stays as-is.

## How it fits your homelab

Both clusters already converge at blade-14's Falcosidekick (the pi-k3s spoke forwards
to `192.168.0.90:3002`). So you only add one webhook output on the **hub**; the spoke
is untouched and its events flow in for free.

```
Falco (blade14 + pi-k3s)
   └─> Falcosidekick (falco ns, blade14)
         ├─> Redis ─> falcosidekick-ui   (unchanged)
         ├─> ntfy                          (unchanged)
         └─> webhook ─> falco-triage (/ingest) ─> SQLite ─> mobile feed   (new)
```

## Layout

```
infrastructure/falco-triage/      <- the deploy/ files go here
  namespace.yaml  pvc.yaml  secret.yaml  deployment.yaml  service.yaml  kustomization.yaml
clusters/blade14/falco-triage.yaml  <- the flux/ Kustomization
```
The `app/` dir is the container source (build + push separately).

## Deploy

1. **Build & push the image** to a registry your cluster can pull from (e.g. your Gitea registry):
   ```
   cd app
   docker build -t <registry>/falco-triage:latest .
   docker push <registry>/falco-triage:latest
   ```
   Set that ref in `deployment.yaml` (`image:`).

2. **Make a shared token** and use it in both places:
   ```
   openssl rand -hex 24
   ```
   - App side: copy `secret.example.yaml` → `secret.yaml`, set `webhook-secret: <token>`, then `sops --encrypt --in-place secret.yaml`.
   - Falcosidekick side (`falco` namespace): create a secret `falco-triage-webhook` with
     key `customheaders` = `X-Webhook-Secret:<token>`, SOPS-encrypted the same way your
     `ntfy-secret.yaml` is. (Secrets don't cross namespaces, hence two copies of one token.)

3. **Drop the files in:**
   - `deploy/*` → `infrastructure/falco-triage/`
   - `flux/falco-triage.yaml` → `clusters/blade14/` (match `sourceRef.name` and the SOPS
     `secretRef.name` to your existing `clusters/blade14/falco.yaml`).

4. **Wire the webhook** into `infrastructure/falco/helmrelease.yaml` using
   `helmrelease-webhook-snippet.yaml`. For a first smoke test you can inline
   `customHeaders` (option A) instead of the secret; switch to the secret once events flow.

5. **Commit.** Flux reconciles, Falco hot-reloads Falcosidekick, events start landing.
   Reach the feed over your tailnet the same way you reach the UI today.

## Verify

```
# trigger a Falco rule from any pod
kubectl exec -it <some-pod> -- /bin/sh -c 'cat /etc/shadow'   # "Read sensitive file untrusted"
# then check ingestion
kubectl -n falco-triage logs deploy/falco-triage
```

## Config (env)

| var             | default          | meaning                                  |
|-----------------|------------------|------------------------------------------|
| `TRIAGE_SECRET` | (none)           | shared token; must match the webhook header |
| `DB_PATH`       | `/data/triage.db`| SQLite path                              |
| `POLL_SECONDS`  | `15`             | feed auto-refresh interval               |
| `RETENTION_DAYS`| `30`             | events older than this are pruned on write |

## Next

The rules console (validate + git-commit Falco rules, Falco hot-reloads via
`watch_config_files`) slots in as a second tab on this same app.
