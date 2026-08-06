# ADR 0002: Product peer mesh is platform SA config — never per-tenant grants

- Status: **Accepted**
- Date: 2026-08-06
- Supersedes practice: ad-hoc tenancy migrations that grant OAuth audiences or
  ReBAC permissions “for a customer” or “to unblock chat”
- Related: [ADR 0001](0001-runtime-service-contract-registry.md),
  [PERMISSION_REGISTRATION.md](../PERMISSION_REGISTRATION.md),
  [IDENTITY_AND_AUTHORIZATION.md](../IDENTITY_AND_AUTHORIZATION.md)

## Context

Product features (e.g. Opportunities matching → platform chat-agent) failed in
production with:

```text
Requested audience 'https://api.stawi.org/chat-agent' has not been whitelisted
by the OAuth 2.0 Client
```

Deploy already listed `/chat-agent` in `requested_audience_paths`. The gap was
**platform service-account contract data** (Hydra recipients + SA ReBAC grants)
for the **product bot** `opportunities-matching`, not missing authorization for
individual tenants or logged-in candidates.

A recurring wrong response is to write dated SQL that “grants chat to matching”
or, worse, per-tenant / per-customer permission rows. That does not scale, confuses
planes, and will be reinvented incorrectly every time a product adds a peer.

## Decision

### Three access modes — pick the lightest that fits

| Mode | Principal | When to use | Config required |
|------|-----------|-------------|-----------------|
| **U. User-scoped platform self-service** | Human JWT (`sub` = profile) | Location, devices, own profile, personal LLM chat, settings, files — **tied to the user** | Login + partition membership + `ROLE_MEMBER` (default on access) + public client baseline audiences (**automatic**) |
| **A. Product edge (SPA → product API)** | Human JWT | Product domain (matching, jobs, checkout) | Explicit product audiences on SPA (`/matching`, …) + partition access |
| **B. Product peer mesh (S2S BFF)** | Product SA bot | Product server must call a peer on behalf of many subjects or own domain secrets | Consumer **platform SA** recipients + SA grants (once for the product bot — never per tenant) |

**Logged-in users must not need tenancy migrations or SA grant rows for mode U.**

**Logged-in users must not need per-tenant grants for mode B either** — only the product SA is wired once; all members of the product inherit via the BFF.

### Mode U — user-scoped platform baseline (default for personal APIs)

After login, a partition **member** can call user-tied platform services with **their own JWT**:

| Audience path | Namespace | Member may (examples) | On public clients |
|---------------|-----------|------------------------|-------------------|
| `/profile` | `service_profile` | view/update own profile, contacts, addresses | **Auto** baseline |
| `/devices` | `service_device` | register/link device, keys, presence, logs | **Auto** baseline |
| `/geolocation` | `service_geolocation` | **ingest location**, view tracks/nearby | **Auto** baseline |
| `/chat-agent` | `service_chat_agent` | create session / turn (own `subject_id`) | **Auto** baseline |
| `/files` | `service_file` | upload/view content | **Auto** baseline |
| `/settings` | `service_setting` | view/manage settings | **Setup only** — explicit SPA recipient |
| `/notification` | `service_notification` | search/status (or send via product) | **Setup only** — explicit SPA recipient |

**How this stays low-config:**

1. **OAuth:** Hydra client sync injects **baseline** audiences for every `type=public` client (`ensurePublicPlatformAudiences`) — same idea as `ensureTenancyAudience` for internal bots. Product APIs (`/matching`, `/jobs`, …) and **settings / notification** remain explicit recipients at product setup.
2. **ReBAC:** Access grant → default partition role `member` → `BuildRoleTuples` writes `#member` on every registered namespace that declares `ROLE_MEMBER` → OPL permits resolve permissions. **No per-user permission rows.**
3. **Proto:** Baseline platform services’ `ROLE_MEMBER` bindings include self-service write perms (e.g. `location_ingest`, `device_manage`, `chat_agent_turn`). Keep admin-only actions on owner/admin.

Users call baseline services **directly** when the SPA has the audience (auto) and the API is personal. Settings and notifications require the product to opt in via `oauth_client_recipients` (or equivalent SPA setup).

### Mode B — BFF when the product owns the flow

Use S2S when the product edge must orchestrate domain logic (placement rebuild, paywalled listing context, multi-step intake owned by matching):

```text
User JWT ──► product (matching) ── SA JWT ──► peer (chat-agent)
                 │                      │
                 │                      └── ReBAC: matching bot profile_id
                 └── subject_id = user profile_id (body)
```

Either path is valid for chat-agent:

- **Direct (U):** SPA → `/chat-agent` with user JWT; member has `chat_agent_turn`.
- **BFF (B):** SPA → `/matching`; matching SA has peer contract (recipients + grants).

### Three gates for every S2S peer edge (all required)

| # | Gate | Config surface | Failure mode if missing |
|---|------|----------------|-------------------------|
| 1 | Request audience | Deploy / Frame `OAUTH2_REQUESTED_AUDIENCES` / `requested_audience_paths` | Token mint omits `aud` |
| 2 | Hydra whitelist | `oauth_client_recipients` → Hydra client `audience` | “has not been whitelisted” |
| 3 | Functional ReBAC | SA policy grant on peer namespace + explicit permissions | `permission_denied` after token works |

**Listing a path only in Cloud Run tfvars is necessary but never sufficient.**

`/tenancy` is the only peer with automatic Hydra whitelist assist
(`ensureTenancyAudience` for internal clients). **All other product peers must be
declared on the consumer SA contract** (seed, API update of that SA, or future
automated materialization from the same contract). Do not invent per-tenant SQL.

### Where peer edges live

| Location | Allowed? | Notes |
|----------|----------|--------|
| **Product / platform SA seed or SA API update** (root partition) | **Yes — canonical** | Consumer owns its dependency list |
| **Greenfield auth-contract snapshot** | Yes | Must stay consistent with live product topology for wipe/reseed |
| **Dated migration** | **Live-cluster repair only** | Fold intent into product contract / greenfield; never model “per customer” |
| **Per-tenant / per-customer grant rows for S2S peers** | **Forbidden** | Wrong plane |
| **Auto-grant every internal SA the peer** | **Forbidden** | Breaks least privilege |
| **Hand Keto tuples in app startup** | **Forbidden** | Use SA policy pipeline |

### Consumer checklist (mandatory when a product starts calling a peer)

When product service **P** starts calling platform service **S**:

1. **Deploy:** add `/{S}` to P’s `requested_audience_paths` (colony / frame-cloudrun).
2. **Auth contract for P’s SA** (same change set or blocking follow-up — never “later in prod”):
   - `oauth_client_recipients`: `https://api.stawi.org/{S}` (canonical base URL).
   - SA authorization grant: namespace of S (e.g. `service_chat_agent`) with scope
     `partition_tree` (or documented narrower scope).
   - Explicit permissions required by the RPCs P calls (least privilege; read
     callee proto `method_permissions`).
3. **Owner of S** still registers its namespace via Frame permission registration
   (ADR 0001). Grants stay pending until registration succeeds — fail-closed is OK.
4. **Client code:** use authenticated Connect/OAuth client (token actually attached).
5. **CI / review:** reject PRs that add (1) without (2), or that add tenant-scoped
   rows “so customers can chat.”
6. **After DB change:** clear consumer client `synced_at` (Hydra re-sync) and bump
   SA policy `generation` / `status=pending` (Keto re-materialize). Existing
   pipelines do this; do not skip.

### Provider checklist (when introducing a new platform service)

Shipping **S** alone is not enough:

1. Seed owner SA for S (own namespace grant + own outbound recipients).
2. Document **known consumers** and either:
   - update each consumer’s SA contract in the **same program of work**, or
   - leave consumers unenabled until their contract is updated (fail-closed).
3. Do **not** reverse-wire every SA. Only declared consumers.
4. `make new-service` only scaffolds **S**. It does **not** update consumers —
   that is intentional least privilege, not “consumers auto-work.”

### What “new customer works from get-go” means

| Event | Required work | Not required |
|-------|---------------|--------------|
| New tenant / partition | Partition seed, SPA client (+ optional **product** audiences), access grants for humans | Per-user `chat_agent_*` / location / device grants |
| New user logs in as member | Login + partition membership | Any SA grant row; any extra OAuth migration for platform baseline |
| User sends location / registers device / personal LLM chat | Already covered by mode **U** | Admin role or product SA |
| Product BFF enables chat-agent for domain orchestration | **One** update to product SA peer contract (mode **B**) | Migration per tenant |

Platform SAs use plane-1 service access and `partition_tree` grants so **one**
bot policy covers all partitions the product operates in.

### Forbidden patterns (do not reintroduce)

1. **“Grant this customer chat”** SQL or admin one-offs for S2S peers.
2. **Only** fixing deploy env after Hydra whitelist errors without SA grants
   (or only grants without recipients).
3. Putting peer edges only in comments / runbooks without seed or SA API.
4. Granting `chat_agent_manage` (or full RoleService) when the consumer only
   needs `chat_agent_turn` / `chat_agent_view` — still use least privilege.
5. Direct SPA → chat-agent as the default product path without an explicit product
   decision and SPA recipient + human role_bindings workstream.
6. Treating dated repair migrations as the product model instead of folding into
   the consumer SA contract / greenfield.

### Incident class: matching → chat-agent (2026-08)

| What went wrong | Correct fix class |
|-----------------|-------------------|
| Matching tfvars requested `/chat-agent` | Gate 1 only |
| Auth contract for `opportunities-matching` lacked recipient + `service_chat_agent` grant | Gate 2 + 3 — **platform SA**, not tenants |
| Chat-agent seed only created owner SA | Expected; consumers must be declared separately |
| Temptation: “migrate each customer” | **Reject** — plane A already sufficient once plane B is fixed |

Live repair migration (if present):
`apps/tenancy/migrations/0001/20260806_01_matching_chat_agent_audience.sql`
is **cluster repair**, not a template for future customer work.

## Consequences

- Product teams own their peer list; identity does not hardcode a service mesh graph.
- New tenants and users inherit product features without identity migrations.
- Incomplete consumer contracts fail closed (Hydra or ReBAC) instead of silent
  heuristic fallbacks.
- Reviewers have a checklist and a hard “forbidden” list.
- Future automation (materialize recipients/grants from a single peer declaration)
  must preserve consumer-owned least privilege — not “all internal SAs get all peers.”

## Enforcement (process)

- Code review: any new `requested_audience_paths` entry requires matching
  `oauth_client_recipients` + SA grant for that product SA (or a tracked API
  update of that SA in the same release).
- Migrations: titles/comments must not say “for customer X”; peer edges name the
  **client_id** / SA of the product bot.
- Ops docs for each consumer (e.g. opportunities `docs/ops/chat-agent-integration.md`)
  must restate the BFF + three-gate model and link here.

## References

- `docs/PERMISSION_REGISTRATION.md` — audiences vs ReBAC; registration pipeline
- `docs/IDENTITY_AND_AUTHORIZATION.md` — `sub === profile_id`
- `apps/tenancy/migrations/DIFF_NOTES.md` — greenfield vs live repair
- `tools/migrations/new-service.sh` — scaffolds **new** SA only
- Opportunities: `docs/ops/chat-agent-integration.md`
