# ADR-0007 — Synapse message rate-limit tuning for the p43 SSH agent

- **Status:** Accepted
- **Date:** 2026-04

## Context

The p43 SSH agent forwards every SSH `request_identities` and `sign` call as a
Matrix message and waits for a response from the UI.  Under parallel SSH
operations (e.g. `ssh-add -l` called concurrently from multiple processes, or
`git rebase` issuing many sign requests back-to-back) several outbound messages
are sent in rapid succession by the same Matrix user.

Synapse's default `rc_message` rate limit is:

```yaml
rc_message:
  per_second: 0.2
  burst_count: 10
```

This allows a burst of 10 messages and then throttles to one message every 5
seconds.  In practice, after the burst is exhausted, each subsequent send is
delayed by up to 5 s *server-side* (Synapse queues and retries internally).
With even a handful of parallel requests the round-trip time grows to 50+ s,
which causes SSH clients to time out and the agent to return
`agent refused operation`.

Everything runs on the same machine (Synapse in Kubernetes, CLI agent and UI
both macOS processes), so the delay is purely Synapse's rate-limiter, not
network latency.

## Decision

Raise `rc_message` in `homeserver.yaml` to values appropriate for a
single-user, single-room deployment:

```yaml
rc_message:
  per_second: 100
  burst_count: 500
```

These limits are far above any realistic SSH agent burst.  Because this Synapse
instance serves only the p43 room and its users, there is no multi-tenant
abuse risk.

### How to re-apply after a cluster rebuild

When rebuilding the cluster the `matrix-synapse-config` ConfigMap must include
**two** keys: `homeserver.yaml` and the log config file.  Patching with only
`homeserver.yaml` drops the log config, causing Synapse to crash on startup
with `OSError: [Errno 30] Read-only file system` (the ConfigMap mount is
read-only so Synapse cannot regenerate the file).

```bash
# 1. Fetch the current homeserver.yaml (or start from the repo copy):
kubectl get configmap matrix-synapse-config -n matrix \
  -o jsonpath='{.data.homeserver\.yaml}' > /tmp/homeserver.yaml

# 2. Ensure rc_message is set (not commented out):
#    rc_message:
#      per_second: 100
#      burst_count: 500

# 3. Create the log config if it doesn't exist locally:
cat > /tmp/matrix.adviser.com.log.config << 'EOF'
version: 1

formatters:
  precise:
    format: '%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(request)s - %(message)s'

handlers:
  console:
    class: logging.StreamHandler
    formatter: precise

loggers:
  synapse.storage.SQL:
    level: WARNING

root:
  level: WARNING
  handlers: [console]

disable_existing_loggers: false
EOF

# 4. Apply BOTH files in one patch (omitting either drops the other key):
kubectl create configmap matrix-synapse-config -n matrix \
  --from-file=homeserver.yaml=/tmp/homeserver.yaml \
  --from-file=matrix.adviser.com.log.config=/tmp/matrix.adviser.com.log.config \
  --dry-run=client -o yaml | kubectl apply -f -

# 5. Restart Synapse:
kubectl rollout restart deployment/matrix-synapse -n matrix
kubectl rollout status  deployment/matrix-synapse -n matrix
```

## Alternatives considered

- **Per-user exemption via `exempt_user_ids`.**  Synapse supports exempting
  specific users from rate limits.  Cleaner in theory but requires knowing the
  exact Matrix user ID and adds config that's easy to forget.  Raising the
  global limit is simpler and has no practical downside for a single-user
  server.
- **Leave defaults, rely on retries.**  The matrix-sdk retries rate-limited
  sends with backoff, so requests eventually succeed.  But the backoff delay
  (5–60 s) causes SSH timeouts and a degraded user experience.  Not acceptable.

## Consequences

- Parallel SSH agent requests complete in under 1 s round-trip (was 50+ s).
- The ConfigMap patch procedure now explicitly includes both keys; the runbook
  in this ADR and in ADR-0006 must be followed together after a cluster rebuild.
- If the Synapse instance ever becomes multi-tenant these limits must be
  revisited.
