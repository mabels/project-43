# ADR-0006 — Synapse server-side message retention for the p43 Matrix room

- **Status:** Accepted
- **Date:** 2026-04

## Context

The p43 Matrix room (`!KIVRtQYrjdAZZoPEYY:matrix.adviser.com`) accumulates
encrypted sign-request / sign-response message pairs continuously.  The SSH
agent's redact worker cleans up completed transactions asynchronously, but
timed-out requests, CSR/cert registration exchanges, and any other messages
that bypass the redact worker accumulate indefinitely.

Client-side redaction via `p43 matrix purge` (which calls
`room.redact()` per event over the Matrix CS API) is too slow for rooms with
thousands of events: each redaction is a separate HTTP round-trip, and Synapse
rate-limits them.

## Decision

Enable the Synapse built-in **message retention** feature on the homeserver
and activate it on the p43 room only via the `m.room.retention` state event.

### Synapse configuration (`homeserver.yaml` in the `matrix-synapse-config` ConfigMap)

```yaml
retention:
  enabled: true
  # No default_policy — retention only fires on rooms that explicitly
  # set the m.room.retention state event.
  purge_jobs:
    - interval: 1h
```

This enables the retention background job (runs every hour) without imposing
any default lifetime on rooms that have not opted in.

### Room state event

```
PUT /_matrix/client/v3/rooms/!KIVRtQYrjdAZZoPEYY:matrix.adviser.com/state/m.room.retention/
{ "max_lifetime": 28800000 }
```

`28800000 ms = 8 hours`.  Synapse's hourly job purges any event in the room
older than 8 h server-side — no per-event client API calls required.

### How to re-apply after a cluster rebuild

```bash
# 1. Patch the ConfigMap (retention block already in homeserver.yaml; just uncomment):
kubectl edit configmap matrix-synapse-config -n matrix
# Set:  retention:
#         enabled: true
#         purge_jobs:
#           - interval: 1h

# 2. Restart Synapse to pick up the config change:
kubectl rollout restart deployment/matrix-synapse -n matrix

# 3. Get an admin access token from the DB:
kubectl exec -n matrix deployment/matrix-synapse -- python3 -c "
import psycopg2
conn = psycopg2.connect(host='postgres-postgresql.default.svc.cluster.local',
                        database='synapse', user='synapse_user', password='sehrGeheim')
cur = conn.cursor()
cur.execute(\"SELECT user_id, token FROM access_tokens JOIN users \
             ON access_tokens.user_id = users.name WHERE users.admin = 1 LIMIT 1\")
print(cur.fetchone())
"

# 4. Set the retention state event on the room:
kubectl exec -n matrix deployment/matrix-synapse -- curl -s -X PUT \
  'http://localhost:8008/_matrix/client/v3/rooms/%21KIVRtQYrjdAZZoPEYY%3Amatrix.adviser.com/state/m.room.retention/' \
  -H 'Authorization: Bearer <token_from_step_3>' \
  -H 'Content-Type: application/json' \
  -d '{"max_lifetime": 28800000}'

# 5. Verify:
kubectl exec -n matrix deployment/matrix-synapse -- curl -s \
  'http://localhost:8008/_matrix/client/v3/rooms/%21KIVRtQYrjdAZZoPEYY%3Amatrix.adviser.com/state/m.room.retention/' \
  -H 'Authorization: Bearer <token_from_step_3>'
# Expected: {"max_lifetime":28800000}
```

## Alternatives considered

- **Client-side redaction via `p43 matrix purge`.**  Works but is slow (one
  HTTP request per event) and can be rate-limited.  Kept as a manual tool for
  one-off cleanups but not suitable as the primary retention mechanism.
- **Synapse Admin API `purge_history` endpoint.**  Fast (server-side bulk
  delete), but requires a cron job or external scheduler.  The `m.room.retention`
  approach is self-contained within Synapse.
- **Server-wide `default_policy`.**  Would enforce a lifetime on every room on
  the server, including rooms not related to p43.  Rejected — retention should
  be opt-in per room.

## Consequences

- Synapse purges messages in the p43 room automatically every hour without any
  client involvement.
- The `p43 matrix purge` CLI subcommand is retained for manual use.
- Any new p43 Matrix room created in the future must have the `m.room.retention`
  state event set explicitly (it is not applied automatically).
- The ConfigMap edit is idempotent — re-applying the patched YAML on a fresh
  cluster is safe.
