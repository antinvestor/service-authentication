# Interactive Auth Latency Audit — p99 &lt; 1s (platform-controlled)

| Field | Value |
|-------|-------|
| **Date** | 2026-07-21 |
| **Target** | p99 wall-clock **&lt; 1s** for platform-controlled interactive OAuth hops |
| **Edge kill** | ~15s (Cloudflare / gateway) |
| **Ship** | auth service budgets + soft-fail (v1.54.44+) |

## SLO definition

| Path class | p99 target | Notes |
|------------|------------|--------|
| Hydra `GET /oauth2/auth` → 302 | &lt; 500ms | Hydra + edge RTT (ops concern if flaky) |
| Auth `GET /s/login` form | **&lt; 500ms** app work | Soft skip / soft cache |
| Auth session skip accept | **&lt; 800ms** soft | Fall through to form on failure |
| Auth contact submit | **&lt; 900ms** | OTP send may be async downstream |
| Auth OTP verify submit | **&lt; 900ms** | |
| Auth consent | **&lt; 900ms** | Device soft-fail |
| SA token webhook | **&lt; 300ms** cold, ≪50ms warm | |
| Sign private_key_jwt | **&lt; 150ms** | On every M2M mint |
| Social callback | External Google not in SLO | Internal after Google ≤ ~2.5s; parent 5s |

**Exception:** third-party IdP network (Google token exchange) is outside platform p99. We still cap it and keep post-Google work short.

## Live sample (2026-07-21, n=20 sequential `/oauth2/auth`)

- All **302** (no 504 in this sample after Hydra stabilize)
- Times: min ~0.30s, median ~0.47s, max ~2.80s
- **p99 not yet under 1s for Hydra hop alone** when tail spikes (ops: Hydra DB / pool / pod churn)

Login page (app): successful renders logged **~107–135ms** server-side; client RTT ~0.5–1.0s.

## Critical findings (fixed or remaining)

### Fixed in this train (auth service)

| Issue | Impact | Fix |
|-------|--------|-----|
| Session skip hard-fail + 800ms–1.2s device/DB | OAuth abort → 504 | Soft skip → form; cache-first event |
| Form hard-fail on Valkey SET deadline | Error page instead of form | Soft-fail createLoginEvent; detached cache 150ms |
| Consent parent 3s / verify 2s | Allowed multi-second app work | Parents **900ms** |
| Social parent 8s | Long hangs | Parent **5s**; internal profile **800ms** |
| SA webhook cold budget unused | Hydra token_hook hang | Parent budget applied |
| Sign JWT unbounded JWKS | Cascading M2M hang | **150ms** budget |
| Hydra admin HTTP client 30s default | Forgotten context → 30s | Transport **2s** |
| Contact submit unbounded profile | Edge kill risk | Parent **900ms** + sub-timeouts |

### Fixed in resilience train (v1.54.47+)

| Issue | Impact | Fix |
|-------|--------|-----|
| JWKS fetch on every `private_key_jwt` mint | Hydra admin blip → all M2M fails; jti_known on retry | Process-local signing key cache (10m TTL) |
| SA negative cache on timeout | One Hydra blip → 2s of 403 token_hook for all SAs | Negative-cache only definitive misses; 503 on transient |
| Token facade 15s client | Edge hangs | **2s** upstream timeout |
| FedCM id-assertion unbounded | Gateway timeout | Parent **4s**; headless HTTP **3s**; tenancy soft budgets |
| Logout unbounded FedCM purge | Logout hang | Parent **800ms** + Hydra sub-timeouts |

### Remaining / ops (not fully closed by app budgets)

| Issue | Owner | Recommendation |
|-------|--------|----------------|
| Intermittent Hydra `/oauth2/auth` 504 (~15s) | Platform / Hydra | Keep Hydra 2+ ready pods; avoid crashloop rollouts; watch oauth2 DB pooler; HPA already max 10 |
| Hydra startup probe flaky on new pods | Platform | Tune startup probe / readiness; investigate DSN/secret on new RS |
| Profile / notification OTP delivery latency | Profile service | Keep CreateContactVerification async or fast-path; auth already times out soft |
| Hydra DB pooler blips | Platform | `pooler-rw` connection errors under load; scale/pool |

## Budget map (current code)

See `apps/default/service/handlers/latency_budgets.go`.

## Soft-fail policy (do not abort OAuth)

| Step | Soft | Hard |
|------|------|------|
| Soft tenancy / Valkey | Yes | — |
| Session skip / remember-me | Fall through to form | — |
| Login event cache SET | Yes (still render) | Missing client_id |
| Device S2S | Yes | — |
| Consent device | Yes | Incomplete claims / OAuth client resolve |
| OTP wrong code | Retriable form | Locked / exceeded attempts |
| CSRF / state | — | Always hard |

## Verification checklist

```bash
# Hydra redirect reliability
for i in $(seq 1 20); do
  # expect 302 in <1s most of the time
  curl -sS -o /dev/null -w '%{http_code}:%{time_total}\n' --max-time 5 \
    "https://oauth2.stawi.org/oauth2/auth?client_id=...&state=...&code_challenge=...&code_challenge_method=S256&..."
done

# Login form (use Location from above)
curl -sS -o /dev/null -w '%{http_code}:%{time_total}\n' --max-time 5 "$LOGIN_URL"

# Server logs should show login page rendered duration_ms << 500
kubectl logs -n identity -l app.kubernetes.io/name=service-authentication --since=5m \
  | grep -E 'login page rendered|session skip|failed to cache login event'
```

## Follow-up PR candidates

1. Hydra readiness / crashloop investigation on rollout  
2. Distributed tracing dashboards for p50/p95/p99 per route  
3. Optional slim LoginEvent cache payloads (if Valkey SET still races budgets)  

