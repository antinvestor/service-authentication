# Antinvestor Platform — Service Metrics Audit

> Generated: 2026-04-14
> Frame Version (all services): v1.93.9
> Frame PR for tenant-aware telemetry: pitabwire/frame#644

---

## Executive Summary

All 10 Antinvestor services (30+ sub-applications) were analysed for their purpose, exposed APIs, current telemetry state, and essential product metrics. The findings:

| Service | Sub-Apps | Endpoints | Current Metrics | Coverage |
|---------|----------|-----------|----------------|----------|
| authentication | 3 | 35+ HTTP/RPC | None | 0% |
| profile | 4 | 60+ RPC | Partial (devices cache, geolocation) | ~25% |
| notification | 5 | 30+ RPC/HTTP | None | 0% |
| files | 4 | 50+ RPC/HTTP | Dead code (Prometheus struct, never wired) | 0% |
| chat | 2 | 20+ RPC | Good (internal/telemetry/) | ~70% |
| commerce | 1 | 19 RPC | None | 0% |
| payment | 10 | 40+ RPC + webhooks | None (billing has otelconnect only) | ~5% |
| fintech | 7 | 120+ RPC/HTTP | None (audit logging only) | 0% |
| thesa | 1 | 22 HTTP | Minimal (trace ID in errors) | ~5% |
| trustage | 3 | 50+ RPC/HTTP | Good but many instruments unrecorded | ~50% |

**Key insight**: Only 2 of 10 services (chat, trustage) have meaningful custom metrics. The remaining 8 rely entirely on Frame's automatic HTTP/OTel instrumentation (request count, latency) with zero product-specific metrics. The new Frame tenant-aware telemetry (PR #644) will automatically add `tenant_id`/`partition_id` to all traced spans and latency histograms across all services with zero code changes.

---

## 1. service-authentication

### Purpose
Multi-tenant OAuth2/OIDC authentication platform — the Login & Consent Provider for Ory Hydra. Handles user login (contact verification, social login, remember-me), OAuth2 consent, token enrichment webhooks, and multi-tenancy management.

### Sub-Applications

| App | Binary | Protocol | Description |
|-----|--------|----------|-------------|
| `apps/default` | auth-server | HTTP + ConnectRPC | User-facing login/consent/logout, Hydra webhooks, login history API |
| `apps/tenancy` | tenancy-server | ConnectRPC + HTTP | Tenant/partition/service-account CRUD, Hydra client sync, Keto permission management |
| `apps/audit` | audit-server | — | Audit logging |

### Exposed Endpoints

**apps/default — HTTP**
- `GET /s/login` — Login page (Hydra redirect target)
- `POST /s/login/{id}/post` — Contact submission
- `GET /s/verify/contact/{id}` — OTP verification page
- `POST /s/verify/contact/{id}/post` — OTP check
- `POST /s/verify/contact/{id}/resend` — Resend OTP
- `POST /s/social/login/{id}` — Social login initiation (Google/Facebook/Apple/Microsoft)
- `GET|POST /s/social/callback` — Social provider callback
- `GET /s/consent` — OAuth2 consent (auto-approved)
- `GET /s/logout` — Logout handler
- `GET /s/access/workspace` — Workspace selector
- `POST /webhook/enrich/{tokenType}` — Token enrichment (called by Hydra)
- `POST /webhook/sign/private-key-jwt` — Private key JWT signing

**apps/default — ConnectRPC**
- `GetLoginEvent` — Fetch login event by ID
- `ListLoginEvents` — Stream/paginate login events

**apps/tenancy — ConnectRPC**
- `CreateTenant` / `GetTenant` / `ListTenant` / `UpdateTenant` / `RemoveTenant`
- `CreatePartition` / `GetPartition` / `ListPartition` / `GetPartitionParents` / `UpdatePartition` / `RemovePartition`
- `CreatePartitionRole` / `ListPartitionRole` / `UpdatePartitionRole` / `RemovePartitionRole`
- `CreateServiceAccount` / `GetServiceAccount` / `ListServiceAccount` / `UpdateServiceAccount` / `RemoveServiceAccount`
- `CreateClient` / `GetClient` / `ListClient` / `UpdateClient` / `RemoveClient`
- `CreateAccess` / `GetAccess` / `ListAccess` / `RemoveAccess`
- `CreateAccessRole` / `ListAccessRole` / `RemoveAccessRole`
- `CreatePage` / `GetPage` / `ListPage` / `UpdatePage` / `RemovePage`
- `ListServiceNamespaces` / `GrantPermission` / `RevokePermission`

**apps/tenancy — Internal HTTP**
- `/_internal/sync/clients` — Sync all clients to Hydra
- `/_internal/register/permissions` — Register service permission manifest
- `/_internal/opl` — Serve Keto OPL config

### Current Metrics: **None**
Zero application-level telemetry instrumentation.

### Essential Metrics

| Metric | Type | Labels | Where |
|--------|------|--------|-------|
| `auth.login.attempts` | counter | `contact_type`, `client_id` | `LoginEndpointSubmit` |
| `auth.login.completed` | counter | `source` (direct/google/facebook/apple), `is_new_user` | `AcceptLoginRequest` calls |
| `auth.login.failed` | counter | `reason` (rate_limited/verification_failed/bot_blocked) | error paths |
| `auth.login.rate_limited` | counter | `client_id` | `CheckLoginRateLimit` |
| `auth.verification.sent` | counter | `contact_type` | OTP creation |
| `auth.verification.checked` | counter | `result` (success/incorrect/exceeded) | `VerificationEndpointSubmit` |
| `auth.verification.resent` | counter | `contact_type` | resend endpoint |
| `auth.social.initiated` | counter | `provider` | `ProviderLoginEndpointV2` |
| `auth.social.completed` | counter | `provider`, `is_new_user` | callback success |
| `auth.social.failed` | counter | `provider`, `reason` | callback error |
| `auth.consent.granted` | counter | `principal_type` (user/service_account) | `ShowConsentEndpoint` |
| `auth.token.enrichment` | counter | `token_type`, `grant_type`, `path` (fast/slow/db) | webhook |
| `auth.token.enrichment.duration` | histogram | `token_type`, `grant_type` | webhook |
| `auth.session.skip` | counter | — | Hydra skip flow |
| `auth.remember_me.login` | counter | `result` | remember-me attempt |
| `auth.device.created` | counter | `device_type` | device creation |
| `auth.sa.token` | counter | `sa_type`, `grant_type` | SA token enrichment |
| `tenancy.partition.created` | counter | — | partition CRUD |
| `tenancy.sa.created` | counter | `sa_type` | SA creation |
| `tenancy.hydra.sync` | counter | `entity_type`, `result` | Hydra sync |
| `tenancy.permission.granted` | counter | `namespace` | GrantPermission |

---

## 2. service-profile

### Purpose
Identity and presence layer — user/bot/institution profiles, encrypted contacts, contact verification (OTP), rosters, relationships, device management, presence, cryptographic keys, push notifications, settings, and geolocation (geofencing, route tracking, proximity queries).

### Sub-Applications

| App | Binary | Protocol | Description |
|-----|--------|----------|-------------|
| `apps/default` | profile-server | ConnectRPC + REST | Profile CRUD, contacts (encrypted), verification, rosters, relationships, addresses |
| `apps/devices` | device-server | ConnectRPC | Device lifecycle, sessions, presence, crypto keys, push notification, TURN credentials |
| `apps/settings` | settings-server | ConnectRPC | Key/value settings store with history |
| `apps/geolocation` | geolocation-server | ConnectRPC + REST | Location ingestion, geofencing, route tracking, proximity queries |

### Exposed Endpoints (60+)

**ProfileService** (18 RPCs): `GetById`, `GetByContact`, `Search`, `Merge`, `Create`, `Update`, `AddAddress`, `AddContact`, `CreateContact`, `CreateContactVerification`, `CheckVerification`, `RemoveContact`, `SearchRoster`, `AddRoster`, `RemoveRoster`, `AddRelationship`, `DeleteRelationship`, `ListRelationships`
- REST: `GET /public/user/info`, `GET /public/user/relations`

**DeviceService** (17 RPCs): `GetById`, `GetBySessionId`, `Search`, `Create`, `Update`, `Link`, `Remove`, `Log`, `ListLogs`, `GetTurnCredentials`, `AddKey`, `RemoveKey`, `SearchKey`, `UpdatePresence`, `RegisterKey`, `DeRegisterKey`, `Notify`

**SettingsService** (4 RPCs): `Get`, `Set`, `List`, `Search`

**GeolocationService** (19 RPCs): `IngestLocations`, `CreateArea`, `GetArea`, `UpdateArea`, `DeleteArea`, `SearchAreas`, `CreateRoute`, `GetRoute`, `UpdateRoute`, `DeleteRoute`, `SearchRoutes`, `AssignRoute`, `UnassignRoute`, `GetSubjectRouteAssignments`, `GetTrack`, `GetSubjectEvents`, `GetAreaSubjects`, `GetNearbySubjects`, `GetNearbyAreas`

### Current Metrics: **Partial** (~25%)
- **Devices** (`apps/devices/service/caching/metrics.go`): `cache_hits`, `cache_misses`, `rate_limited` counters + tracer spans
- **Geolocation** (`apps/geolocation/service/observability/metrics.go`): `ingestBatchLatency`, `ingestAccepted/Rejected`, `geofenceEvalLatency`, `geofenceTransitions`, `routeDeviationEvalLatency`, `routeDeviationTransitions`, `proximityQueryLatency`
- **Profile & Settings**: Zero instrumentation

### Essential Metrics (gaps)

| Metric | Type | App | Where |
|--------|------|-----|-------|
| `profile.created` | counter | default | `Create` |
| `profile.contact.verification.requested` | counter | default | `CreateContactVerification` |
| `profile.contact.verification.checked` | counter | default | `CheckVerification` |
| `profile.contact.encryption.key_rotation` | counter | default | key rotation queue |
| `profile.roster.bulk_upsert.batch_size` | histogram | default | `AddRoster` |
| `profile.merge` | counter | default | `Merge` |
| `device.created` | counter | devices | `Create` |
| `device.linked` | counter | devices | `Link` |
| `device.presence.updated` | counter | devices | `UpdatePresence` |
| `device.push.notify` | counter | devices | `Notify` |
| `device.turn.issued` | counter | devices | `GetTurnCredentials` |
| `setting.get` | counter | settings | `Get` |
| `setting.set` | counter | settings | `Set` |
| `geolocation.area.created` | counter | geolocation | `CreateArea` |
| `geolocation.route.assigned` | counter | geolocation | `AssignRoute` |

---

## 3. service-notification

### Purpose
Multi-channel, multi-tenant notification platform. Receives notification requests, routes to delivery channels (SMS, email), formats via templates, dispatches to provider integrations. Also includes a full USSD session engine.

### Sub-Applications

| App | Binary | Protocol | Description |
|-----|--------|----------|-------------|
| `apps/default` | notification-server | ConnectRPC | Core notification service — send, receive, route, template, status |
| `apps/integrations/africastalking` | at-worker | Queue + HTTP | Africa's Talking SMS integration |
| `apps/integrations/emailsmtp` | smtp-worker | Queue + HTTP | SMTP email delivery with connection pooling |
| `apps/integrations/smpp` | smpp-worker | Queue + HTTP | SMPP integration (stub) |
| `apps/ussd` | ussd-server | HTTP | USSD session engine with menu tree navigation |

### Exposed Endpoints

**NotificationService** (8 RPCs): `Send` (streaming), `Status`, `StatusUpdate`, `Release` (streaming), `Receive` (streaming), `Search` (streaming), `TemplateSearch` (streaming), `TemplateSave`

**USSD Gateway**: `POST /ussd/gateway/{serviceID}`, `POST /ussd/gateway/{serviceID}/{protocol}`
**USSD Management** (15 REST endpoints): Menu CRUD, translations, service config, queries, sessions

**Integration Webhooks**: `/receive/notification/{routeID}` (AT + SMTP)

### Current Metrics: **None**

### Essential Metrics

| Metric | Type | Labels | Where |
|--------|------|--------|-------|
| `notification.queued` | counter | `channel`, `direction` | `QueueOut`/`QueueIn` |
| `notification.delivered` | counter | `channel`, `provider`, `status` | status update events |
| `notification.failed` | counter | `channel`, `provider`, `reason` | failed status |
| `notification.route.miss` | counter | `direction`, `type` | route not found |
| `notification.template.render` | counter | `template`, `status` | template execution |
| `notification.template.render.duration` | histogram | — | template execution |
| `africastalking.sms.sent` | counter | `status_code_range` | AT client |
| `email.smtp.sent` | counter | `result` | SMTP send |
| `email.smtp.connection.reuse` | counter | — | connection pool |
| `ussd.session` | counter | `service_id`, `outcome` | session complete/abandon |
| `ussd.session.duration` | histogram | `service_id` | session lifecycle |
| `ussd.input.validation.failure` | counter | `service_id`, `menu_id` | input validation |

---

## 4. service-files

### Purpose
Multi-tenant file storage platform — upload, download, thumbnail generation, encryption, versioning, multipart uploads, URL previews, retention policies, access control (ReBAC). Also includes OCR, property catalogue, and URL shortener services.

### Sub-Applications

| App | Binary | Protocol | Description |
|-----|--------|----------|-------------|
| `apps/default` | files-server | ConnectRPC + REST | Core file service (35+ RPCs) |
| `apps/ocr` | ocr-server | ConnectRPC | OCR via Google Vision / Tesseract |
| `apps/property` | property-server | ConnectRPC | Real estate property catalogue |
| `apps/redirect` | redirect-server | ConnectRPC + HTTP | URL shortener with click tracking |

### Exposed Endpoints (50+)

**FilesService** (35 RPCs): `UploadContent`, `CreateContent`, `GetContent`, `GetContentOverrideName`, `HeadContent`, `GetContentThumbnail`, `GetUrlPreview`, `GetConfig`, `GetUserUsage`, `GetStorageStats`, `GetSignedUploadUrl`, `GetSignedDownloadUrl`, `CreateMultipartUpload`, `UploadMultipartPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`, `ListMultipartParts`, `DeleteContent`, `BatchGetContent`, `BatchDeleteContent`, `GetVersions`, `RestoreVersion`, `SetRetentionPolicy`, `GetRetentionPolicy`, `ListRetentionPolicies`, `SearchMedia`, `PatchContent`, `FinalizeSignedUpload`, `GrantAccess`, `RevokeAccess`, `ListAccess`, `DownloadContent`, `DownloadContentRange`
- REST: `/v1/media/upload`, `/v1/media/download/{server}/{id}`, `/v1/media/thumbnail/{server}/{id}`, `/v1/media/search`, `/v1/media/config`

**OCRService** (2 RPCs): `Recognize`, `Status`
**PropertyService** (13 RPCs): Property types, localities, properties, subscriptions
**RedirectService** (7 RPCs + `GET /r/{slug}`): `CreateLink`, `GetLink`, `UpdateLink`, `DeleteLink`, `ListLinks`, `GetLinkStats`, `ListClicks`

### Current Metrics: **Dead code** (0%)
A full `Metrics` struct exists at `apps/default/service/metrics/metrics.go` with Prometheus text exposition, but it is **never wired** in `main.go`. Zero OTel usage.

### Essential Metrics

| Metric | Type | Labels | Where |
|--------|------|--------|-------|
| `files.upload` | counter | `content_type`, `visibility` | `UploadContent` |
| `files.upload.bytes` | counter | `visibility` | upload completion |
| `files.upload.duration` | histogram | — | upload end-to-end |
| `files.download` | counter | `cached` | `GetContent`/`DownloadContent` |
| `files.download.bytes` | counter | — | download completion |
| `files.thumbnail.generated` | counter | `method` | thumbnail queue |
| `files.thumbnail.duration` | histogram | — | thumbnail queue |
| `files.delete` | counter | — | `DeleteContent` |
| `files.multipart.completed` | counter | — | `CompleteMultipartUpload` |
| `files.dedup.hits` | counter | — | hash dedup path |
| `files.authz.denied` | counter | `permission` | authz middleware |
| `redirect.redirects` | counter | — | `GET /r/{slug}` |
| `redirect.unique_clicks` | counter | — | dedup check |
| `ocr.recognize` | counter | `provider`, `outcome` | `Recognize` |
| `ocr.recognize.duration` | histogram | `provider` | `Recognize` |

---

## 5. service-chat

### Purpose
Multi-tenant real-time chat platform — rooms, messaging, subscriptions with roles, real-time presence/typing/read receipts, proposal workflow, sharded device delivery pipeline, offline push notifications, reconnection replay.

### Sub-Applications

| App | Binary | Protocol | Description |
|-----|--------|----------|-------------|
| `apps/default` | chat-server | ConnectRPC | Core chat service — rooms, messages, subscriptions, proposals, replay |
| `apps/gateway` | chat-gateway | ConnectRPC (BiDi stream) | WebSocket gateway for real-time device connections |

### Exposed Endpoints (20+)

**ChatService** (20 RPCs): `SendEvent`, `GetHistory`, `GetEvent`, `GetRoom`, `CreateRoom`, `SearchRooms` (stream), `UpdateRoom`, `DeleteRoom`, `AddRoomSubscriptions`, `RemoveRoomSubscriptions`, `UpdateSubscriptionRole`, `SearchRoomSubscriptions`, `GetSubscriptionSettings`, `UpdateSubscriptionSettings`, `ListProposals`, `SubmitProposal`, `Live`, `ResolveReplayCursor`, `GetLatestReplayCursor`, `ListReplayEvents`

**GatewayService** (1 RPC): `Stream` (BiDi streaming)

### Current Metrics: **Good** (~70%)

**Existing counters** (`internal/telemetry/metrics.go`):
`chat.messages.sent`, `chat.messages.delivered`, `chat.messages.failed`, `chat.messages.dead_lettered`, `chat.rooms.created`, `chat.rooms.deleted`, `chat.subscriptions.added`, `chat.subscriptions.removed` (declared but unused), `chat.outbox.created`, `chat.delivery.queue.processed`, `chat.delivery.queue.retried`, `chat.notifications.sent`, `chat.notifications.failed`, `chat.events.fanout`, `chat.dlq.consumed`, `chat.replay.cursor.resolved`, `chat.replay.events.listed`

**Existing histograms**: `chat.delivery.latency`, `chat.replay.latency`

**Gateway counters**: `gateway.connections.active`, `gateway.connections.total`, `gateway.connections.failed`, `gateway.connections.disconnected`, `gateway.connections.cleaned`, `gateway.connection.duration`

### Gaps

| Metric | Type | Where |
|--------|------|-------|
| `chat.subscriptions.removed` | counter | **Wire callsite** — declared but `.Add()` never called |
| `chat.delivery.online_vs_offline` | counter | separate online/offline delivery |
| `chat.proposals.created/approved/rejected` | counter | proposal workflow (zero metrics) |
| `gateway.messages.rate_limited` | counter | expose `rateLimitedCnt` atomic to OTel |
| `gateway.messages.dropped_backpressure` | counter | expose `droppedMsgs` atomic to OTel |
| `chat.authz.check.duration` | histogram | Keto check latency |

---

## 6. service-commerce

### Purpose
Multi-tenant e-commerce backend — shop management, product catalogue with variants, shopping carts, order management (with stock decrement and idempotency), fulfilment tracking.

### Sub-Applications

| App | Binary | Protocol | Description |
|-----|--------|----------|-------------|
| `apps/default` | commerce-server | ConnectRPC | Single CommerceService |

### Exposed Endpoints (19 RPCs)
`CreateShop`, `GetShop`, `UpdateShop`, `CreateProduct`, `GetProduct`, `ListProducts`, `CreateProductVariant`, `UpdateProductVariant`, `CreateCart`, `GetCart`, `AddCartLine`, `RemoveCartLine`, `CreateOrderFromCart`, `CreateOrder`, `GetOrder`, `ListOrders`, `CreateFulfilment`, `UpdateFulfilment`, `GetFulfilment`

### Current Metrics: **None**

### Essential Metrics

| Metric | Type | Labels | Where |
|--------|------|--------|-------|
| `commerce.orders.created` | counter | `shop_id` | `CreateOrder` |
| `commerce.orders.from_cart` | counter | `shop_id` | `CreateOrderFromCart` |
| `commerce.orders.revenue` | histogram | `currency_code` | order amount |
| `commerce.carts.created` | counter | `shop_id` | `CreateCart` |
| `commerce.carts.converted` | counter | — | cart→order conversion |
| `commerce.stock.decrements` | counter | — | stock update |
| `commerce.stock.insufficient` | counter | — | stock-out events |
| `commerce.fulfilments.created` | counter | — | `CreateFulfilment` |
| `commerce.orders.fulfilled` | counter | — | full fulfilment promotion |
| `commerce.shops.created` | counter | — | `CreateShop` |
| `commerce.order.creation.duration` | histogram | — | order creation latency |

---

## 7. service-payment

### Purpose
Payment orchestration platform — outbound/inbound payment routing, payment prompts (STK push), payment links, double-entry ledger, usage-based billing engine. Six payment provider integrations (M-Pesa, Airtel, MTN, Stripe, Polar, Jenga).

### Sub-Applications

| App | Binary | Protocol | Description |
|-----|--------|----------|-------------|
| `apps/default` | payment-server | ConnectRPC | Core payment orchestrator |
| `apps/ledger` | ledger-server | ConnectRPC | Double-entry bookkeeping |
| `apps/billing` | billing-server | ConnectRPC | Usage-based billing engine |
| `apps/integrations/mpesa` | mpesa-worker | Queue + HTTP | M-Pesa integration |
| `apps/integrations/airtel` | airtel-worker | Queue + HTTP | Airtel Money integration |
| `apps/integrations/mtn` | mtn-worker | Queue + HTTP | MTN MoMo integration |
| `apps/integrations/stripe` | stripe-worker | Queue + HTTP | Stripe integration |
| `apps/integrations/polar` | polar-worker | Queue + HTTP | Polar integration |
| `apps/integrations/jenga-api` | jenga-worker | Queue + HTTP | Jenga API integration |

### Exposed Endpoints (40+)

**PaymentService** (9 RPCs): `Send`, `Status`, `StatusUpdate`, `Release`, `Receive`, `InitiatePrompt`, `CreatePaymentLink`, `Search` (stream), `Reconcile`

**LedgerService** (11 RPCs): `SearchLedgers`, `CreateLedger`, `UpdateLedger`, `SearchAccounts`, `CreateAccount`, `UpdateAccount`, `SearchTransactions`, `CreateTransaction`, `ReverseTransaction`, `UpdateTransaction`, `SearchTransactionEntries`

**BillingService** (24 RPCs): Catalog/plan/component/tier CRUD, subscriptions, usage event ingestion, billing runs, invoicing, credit grants, discounts

**Integration Webhooks**: M-Pesa (5 endpoints), Airtel (2), MTN (2), Stripe (1), Polar (1), Jenga (2)

### Current Metrics: **None** (billing has `otelconnect` interceptor only)

### Essential Metrics

| Metric | Type | Labels | Where |
|--------|------|--------|-------|
| `payment.sent` | counter | `payment_type`, `currency` | `Send` |
| `payment.received` | counter | `payment_type`, `currency` | `Receive` |
| `payment.amount` | histogram | `currency`, `direction` | monetary volume |
| `payment.failed` | counter | `payment_type`, `provider` | failed status |
| `payment.routing.failure` | counter | — | no matching route |
| `payment.processing.duration` | histogram | — | end-to-end latency |
| `payment.prompt.initiated` | counter | — | `InitiatePrompt` |
| `ledger.transaction.created` | counter | `type`, `currency` | `CreateTransaction` |
| `ledger.transaction.amount` | histogram | `currency` | monetary volume |
| `ledger.transaction.conflict` | counter | — | idempotency conflicts |
| `ledger.transaction.reversed` | counter | `currency` | `ReverseTransaction` |
| `billing.run` | counter | `state` | `RunBilling` |
| `billing.run.duration` | histogram | — | billing pipeline |
| `billing.invoice.issued` | counter | `currency` | `IssueInvoice` |
| `billing.usage.ingested` | counter | `metric_key` | `IngestUsageEvent` |
| `billing.credit.granted` | counter | `currency` | `GrantCredit` |
| `provider.webhook.callback` | counter | `provider`, `event_type` | all webhooks |
| `provider.api.call` | counter | `provider`, `operation` | outbound API |
| `provider.api.duration` | histogram | `provider` | outbound API latency |

---

## 8. service-fintech

### Purpose
Core banking platform for microfinance — organizational hierarchy, KYC, loan lifecycle, savings accounts, investor funding, transfer orders, payment routing, group-lending workflows (Stawi), direct-to-client lending (Seed).

### Sub-Applications

| App | Binary | Protocol | Description |
|-----|--------|----------|-------------|
| `apps/identity` | identity-server | ConnectRPC + REST | Organizations, workforce, clients, groups, KYC, forms |
| `apps/loans` | loans-server | ConnectRPC | Loan products, requests, accounts, repayments, penalties, restructuring, disbursements |
| `apps/savings` | savings-server | ConnectRPC | Savings products, accounts, deposits, withdrawals, interest |
| `apps/operations` | operations-server | ConnectRPC | Transfer orders, incoming payments, allocation |
| `apps/funding` | funding-server | ConnectRPC | Investor accounts, capital deployment, loss absorption |
| `apps/stawi` | stawi-server | REST | Group-lending workflow callback engine |
| `apps/seed` | seed-server | REST | DTC lending with credit profile progression |

### Exposed Endpoints (120+)

**IdentityService** (52 RPCs): Organization/OrgUnit/Branch/Investor/SystemUser/WorkforceMember/Department/Position/PositionAssignment/InternalTeam/TeamMembership/AccessRoleAssignment CRUD, ClientGroup/Membership CRUD, ClientData lifecycle + verification, FormTemplate/FormSubmission CRUD
**FieldService** (15 RPCs): Agent/Client CRUD, hierarchy, reassignment, relationships
**LoanManagementService** (31 RPCs): Product/Request/Account/Repayment/Penalty/Restructure/Reconciliation/Disbursement lifecycle
**SavingsService** (19 RPCs): Product/Account/Deposit/Withdrawal/InterestAccrual lifecycle
**OperationsService** (4 RPCs): `TransferOrderExecute`, `TransferOrderSearch`, `IncomingPaymentNotify`, `PaymentAllocate`
**FundingService** (7 RPCs): Investor account lifecycle, `FundLoan`, `AbsorbLoss`
**Stawi** (20 REST endpoints): Group formation → tenure → period → loan window → offer → disburse → payment identify/allocate
**Seed** (3 REST endpoints): Loan requests, credit profiles, paid-off hook

### Current Metrics: **None** (audit interceptor + event logging only)

### Essential Metrics

| Metric | Type | Labels | Where |
|--------|------|--------|-------|
| `fintech.loan.request` | counter | `product_id`, `currency`, `status` | `LoanRequestSave/Approve/Reject` |
| `fintech.loan.disbursement` | counter | `product_id`, `currency` | `DisbursementCreate` |
| `fintech.loan.disbursement.amount` | histogram | `currency` | capital deployed |
| `fintech.loan.repayment` | counter | `currency`, `type` | `RepaymentRecord` |
| `fintech.loan.status_transition` | counter | `from`, `to` | state machine |
| `fintech.loan.restructure` | counter | `product_id` | `LoanRestructureCreate` |
| `fintech.savings.deposit` | counter | `currency` | `DepositRecord` |
| `fintech.savings.deposit.amount` | histogram | `currency` | deposit volume |
| `fintech.savings.withdrawal` | counter | `currency` | `WithdrawalRequest` |
| `fintech.transfer.order` | counter | `order_type`, `status` | `TransferOrderExecute` |
| `fintech.transfer.order.amount` | histogram | `currency` | money moved |
| `fintech.transfer.order.duration` | histogram | `order_type` | ledger posting latency |
| `fintech.payment.incoming` | counter | `strategy` | identified vs unidentified |
| `fintech.funding.allocation` | counter | `fully_funded` | `FundLoan` |
| `fintech.client.created` | counter | — | `ClientSave` |
| `fintech.client.kyc.verified` | counter | `result` | `ClientDataVerify` |

---

## 9. service-thesa

### Purpose
Backend for Frontend (BFF) — definition-driven UI API gateway. Translates YAML-declared UI definitions into backend HTTP calls using OpenAPI specs. Provides capability resolution (Keto ReBAC), global search, analytics queries (TimescaleDB), and file proxying.

### Sub-Applications

| App | Binary | Protocol | Description |
|-----|--------|----------|-------------|
| `apps/default` | thesa-bff | HTTP | Single BFF application |

### Exposed Endpoints (22 HTTP)

**UI routes**: `/ui/capabilities`, `/ui/capabilities/batch-check`, `/ui/navigation`, `/ui/pages/{id}`, `/ui/pages/{id}/data`, `/ui/forms/{id}`, `/ui/forms/{id}/data`, `/ui/schemas/{id}`, `/ui/commands/{id}`, `/ui/actions/{id}`, `/ui/resources/{type}/search`, `/ui/resources/{type}/{id}`, `/ui/resources/{type}`, `/ui/search`, `/ui/lookups/{id}`, `/ui/upload`, `/ui/download/{id}`

**Analytics routes**: `/api/analytics/services`, `/api/analytics/metrics`, `/api/analytics/timeseries`, `/api/analytics/distribution`, `/api/analytics/top`

### Current Metrics: **Minimal** (~5%)
Only trace ID extraction in error responses. Request logging middleware logs duration but doesn't record OTel metrics.

### Essential Metrics

| Metric | Type | Labels | Where |
|--------|------|--------|-------|
| `thesa.request.duration` | histogram | `handler`, `status_code` | request middleware |
| `thesa.requests` | counter | `handler`, `status_code` | request middleware |
| `thesa.capability.resolution.duration` | histogram | `cache_hit` | `Resolver.Resolve` |
| `thesa.capability.cache.hits` | counter | — | cache hit path |
| `thesa.capability.cache.misses` | counter | — | cache miss path |
| `thesa.capability.batch_check.failures` | counter | — | Keto BatchCheck fallback |
| `thesa.backend.request.duration` | histogram | `service_id`, `operation_id` | `OpenAPIOperationInvoker` |
| `thesa.backend.errors` | counter | `service_id`, `error_type` | backend call failures |
| `thesa.command.executions` | counter | `command_id`, `success` | `CommandExecutor` |
| `thesa.search.provider.duration` | histogram | `provider_id` | search fan-out |
| `thesa.analytics.query.duration` | histogram | `query_type` | analytics engine |
| `thesa.file.upload.bytes` | counter | — | upload proxy |

---

## 10. service-trustage

### Purpose
Multi-tenant workflow automation engine — contract-driven state transitions with JSON Schema validation, CEL-based event routing, connector adapters for external integrations, scheduling (retry, timeout, timer, signal, scope). Also includes a form definition/submission store and a virtual queue management service.

### Sub-Applications

| App | Binary | Protocol | Description |
|-----|--------|----------|-------------|
| `apps/default` | trustage-server | ConnectRPC + HTTP | Core orchestration engine |
| `apps/formstore` | formstore-server | HTTP | Form definition and submission store |
| `apps/queue` | queue-server | HTTP | Virtual queue management with counters and SLA |

### Exposed Endpoints (50+)

**WorkflowService** (4 RPCs): `CreateWorkflow`, `GetWorkflow`, `ListWorkflows`, `ActivateWorkflow`
**EventService** (2 RPCs): `IngestEvent`, `GetInstanceTimeline`
**RuntimeService** (6 RPCs): `ListInstances`, `RetryInstance`, `ListExecutions`, `GetExecution`, `RetryExecution`, `ResumeExecution`, `GetInstanceRun`
**SignalService** (1 RPC): `SendSignal`
**HTTP**: Form submission, webhook receive, health/ready checks

**Formstore** (10 REST endpoints): Form definition CRUD, submission CRUD
**Queue** (22 REST endpoints): Queue/item/counter lifecycle, stats

### Current Metrics: **Moderate** (~50%)

**Existing instruments** (`pkg/telemetry/metrics.go`): 16 OTel instruments registered. Active: `engine.executions.total`, `engine.dispatch.latency_ms`, `engine.commit.latency_ms`, `engine.stale_executions.total`, `events.ingested.total`, `events.routed.total`, scheduler gauges.

**Formstore** (`apps/formstore/service/business/telemetry.go`): 7 instruments, mostly active.
**Queue** (`apps/queue/service/business/telemetry.go`): 9 instruments, mostly active.

### Gaps — Defined but Never Recorded

| Metric | Status | Fix |
|--------|--------|-----|
| `engine.transitions.total` | Defined, no `.Add()` | Wire in `Commit()` |
| `engine.retries.total` | Defined, no `.Add()` | Wire in retry schedulers |
| `engine.contract_violations.total` | Defined, no `.Add()` | Wire in schema validation |
| `engine.execution.latency_ms` | Defined, no `.Record()` | Wire dispatch-to-commit time |
| `connector.calls.total` | Defined, no `.Add()` | Wire in `ExecutionWorker` |
| `connector.latency_ms` | Defined, no `.Record()` | Wire in `ExecutionWorker` |
| `formstore.schema.validation.errors` | Defined, no `.Add()` | Wire in validation error path |
| `queue.enqueue.errors` | Defined, no `.Add()` | Wire in enqueue error path |
| `queue.dequeue.errors` | Defined, no `.Add()` | Wire in dequeue error path |

### Additional Essential Metrics

| Metric | Type | Where |
|--------|------|-------|
| `engine.instances.active` | gauge | running instances per tenant |
| `scheduler.timer_fired` | counter | timer scheduler |
| `scheduler.signal_delivered` | counter | signal scheduler |
| `queue.wait_time_ms` | histogram | joined_at → called_at |
| `queue.service_time_ms` | histogram | service_start → service_end |
| `queue.sla_breach` | counter | exceeded `sla_minutes` |
| `queue.depth` | gauge | current waiting items |

---

## Implementation Priority

### Tier 1 — Highest Business Impact (implement first)
1. **service-authentication** — Every user interaction starts here; login failures/latency are invisible today
2. **service-payment** — Financial transactions with zero observability; routing failures are silent
3. **service-fintech** — Core banking with zero metrics; PAR30 and disbursement volume are critical

### Tier 2 — High Operational Value
4. **service-notification** — Delivery failures are invisible; provider health unknown
5. **service-files** — Dead metrics code needs wiring; upload/download volumes unknown
6. **service-profile** — Contact verification (shared with auth) needs coverage

### Tier 3 — Existing Coverage + Gaps
7. **service-trustage** — Wire the 9 defined-but-unrecorded instruments
8. **service-chat** — Wire `subscriptions.removed`, add proposal metrics
9. **service-commerce** — New service, lower traffic, but stock-outs need visibility
10. **service-thesa** — BFF gateway metrics are useful but most backend metrics come from the services it proxies

### Cross-Cutting (all services get for free with Frame upgrade)
- `tenant_id` and `partition_id` on all traced spans and latency histograms
- `TenantAttributes(ctx)` helper for custom product metrics
- `WithTenantAttributes(ctx)` metric option for counters/histograms
