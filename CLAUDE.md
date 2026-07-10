# Authentication Service

## Overview

This is a multi-tenant OAuth2/OpenID Connect authentication service built on **Ory Hydra**. It provides:

- **OAuth2 Authorization Code Flow** with PKCE support
- **Contact-based authentication** (email/phone verification codes)
- **Social login** (Google, Facebook)
- **Service Account authentication** for machine-to-machine communication (managed via tenancy service)
- **Multi-tenancy** with tenant/partition isolation
- **Device tracking** for session management

## Identity model (do not drift)

| Concept | Meaning |
|---------|---------|
| **`profile_id`** | **Acting principal.** Permissions (Keto) are always granted to profiles (users or bot SAs). |
| **`client_id`** | OAuth2 client used at login / token issuance; identifies which **partition** the flow belongs to. **Not** a Keto subject. |
| **JWT `sub`** | Wire claim; may equal `client_id` on machine tokens. Authorization uses `profile_id` via Frame `GetProfileID()`. |

Full write-up: [`docs/IDENTITY_AND_AUTHORIZATION.md`](docs/IDENTITY_AND_AUTHORIZATION.md).

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Clients                                         │
│                    (Web Apps, Mobile Apps, Services)                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Ory Hydra                                       │
│                    (OAuth2/OIDC Authorization Server)                        │
│                                                                              │
│  Endpoints:                                                                  │
│  • /oauth2/auth      - Authorization endpoint                               │
│  • /oauth2/token     - Token endpoint                                       │
│  • /oauth2/revoke    - Token revocation                                     │
│  • /userinfo         - User info endpoint                                   │
└─────────────────────────────────────────────────────────────────────────────┘
          │                         │                         │
          │ login_challenge         │ consent_challenge       │ token webhook
          ▼                         ▼                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      Authentication Service (this repo)                      │
│                                                                              │
│  User-facing endpoints:                                                      │
│  • /s/login           - Login page (redirected from Hydra)                  │
│  • /s/consent         - Consent page (auto-approved)                        │
│  • /s/logout          - Logout handling                                     │
│  • /s/verify/contact  - Contact verification                                │
│  • /s/social/login    - Social provider login                               │
│                                                                              │
│  Webhook endpoints:                                                          │
│  • /webhook/enrich/{tokenType} - Token enrichment (called by Hydra)         │
└─────────────────────────────────────────────────────────────────────────────┘
          │                         │                         │
          ▼                         ▼                         ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  Profile Service │  │ Partition Service│  │  Device Service  │
│  (user profiles) │  │ (multi-tenancy)  │  │ (device tracking)│
└──────────────────┘  └──────────────────┘  └──────────────────┘
```

## Directory Structure

```
service-authentication/
├── apps/
│   ├── default/                    # Main authentication app
│   │   ├── cmd/                    # Entry point
│   │   ├── config/                 # Configuration
│   │   ├── service/
│   │   │   ├── handlers/           # HTTP handlers (see handlers/claude.md)
│   │   │   ├── hydra/              # Hydra client (see hydra/claude.md)
│   │   │   ├── models/             # Data models
│   │   │   └── repository/         # Database repositories
│   │   ├── static/                 # CSS, JS assets
│   │   ├── tmpl/                   # HTML templates
│   │   ├── tests/                  # Integration tests
│   │   └── utils/                  # Utility functions
│   │
│   └── tenancy/                    # Tenancy management service
│       └── service/
│           ├── business/           # Business logic (incl. service accounts)
│           ├── handlers/           # gRPC handlers
│           ├── authz/              # Keto ReBAC authorization
│           └── events/             # Event handlers (partition sync, authz sync)
│
└── internal/
    └── tests/                      # Shared test utilities
```

## Token Enrichment Flow

### How Tokens Are Enriched

Token claims are added at two points:

1. **Consent Stage** (`/s/consent`) - Primary enrichment for user tokens and service account tokens
2. **Webhook Stage** (`/webhook/enrich`) - Additional enrichment and service account handling

### Scope-to-Role Mapping Convention

Service accounts use a two-layer naming convention:

- **Scopes** (Hydra/OAuth2 level): Short form from frame constants
  - `system_int` (`openid.ConstSystemScopeInternal`) for internal service accounts
  - `system_ext` (`openid.ConstSystemScopeExternal`) for external service accounts
- **Roles** (token claims): Long form for semantic clarity
  - `system_internal` for internal service accounts
  - `system_external` for external service accounts

The scope determines which role is assigned in the token claims.

### Claims Added to Tokens

| Claim | Source | Description | When Set |
|-------|--------|-------------|----------|
| `tenant_id` | Partition Service | Tenant identifier for multi-tenancy | Consent |
| `partition_id` | Partition Service | Partition (OAuth2 client) identifier | Consent |
| `roles` | Hardcoded / SA type | User roles (`["user"]`, `["system_internal"]`, or `["system_external"]`) | Consent/Webhook |
| `device_id` | Device Service | Unique device identifier | Consent (user only) |
| `login_id` | Device Session | Session ID that created the token | Consent (user only) |
| `profile_id` | Subject | User's or service account's profile identifier | Consent |

### Token Refresh Behavior

**Important Design Decision:** Token claims are set at consent time and remain constant for the token family's lifetime.

During token refresh:
- **Regular users**: Claims pass through unchanged (device_id, login_id represent original session)
- **Service accounts**: Claims pass through from session; webhook validates non-user roles
- **System internal/external**: Roles are set to `["system_internal"]` or `["system_external"]`

This means:
- Role changes for users require re-authentication
- Device/session binding remains constant (this is intentional for security)
- Tenancy claims are stable (tied to OAuth2 client)

## Service Accounts

Service accounts are managed by the **tenancy service** (`apps/tenancy`). They provide machine-to-machine authentication via OAuth2 `client_credentials` grant.

### Types

- **internal** (`system_int` scope) - For service-to-service communication within the platform
- **external** (`system_ext` scope) - For external API consumers (replaces the legacy API key system)

### How Service Accounts Work

1. **Creation**: `CreateServiceAccount` in the tenancy business layer creates a child partition as a Hydra OAuth2 client with `client_credentials` grant type
2. **Authentication**: The service account authenticates via `client_credentials` grant to get an access token
3. **Token Enrichment**: The webhook enriches the token with `tenant_id`, `partition_id`, `profile_id`, and the appropriate role
4. **Authorization**: Keto ReBAC tuples grant the service account permissions per audience namespace

## Key Configuration

Environment variables (see `apps/default/config/config.go`):

| Variable | Default | Description |
|----------|---------|-------------|
| `SESSION_REMEMBER_DURATION` | `0` | Seconds to remember login session |
| `CACHE_NAME` | `defaultCache` | Cache instance name |
| `CACHE_URI` | `mem://defaultCache` | Cache connection (NATS, memory, etc.) |
| `SECURE_COOKIE_HASH_KEY` | *hardcoded* | **Must override in production** |
| `SECURE_COOKIE_BLOCK_KEY` | *hardcoded* | **Must override in production** |
| `EXPOSE_ERRORS` | `false` | Show detailed errors to users |
| `AUTH_PROVIDER_GOOGLE_*` | - | Google OAuth2 configuration |
| `AUTH_PROVIDER_META_*` | - | Facebook OAuth2 configuration |

## Testing

```bash
# Run all tests
go test ./...

# Run handler tests (requires Docker for containers)
go test ./apps/default/service/handlers/... -v

# Run tenancy tests
go test ./apps/tenancy/... -v

# Run with coverage
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## Common Tasks

### Adding a New Login Provider

1. Add provider configuration to `config/config.go`
2. Register provider in `handlers/init_server.go` `setupAuthProviders()`
3. Add callback handling in `handlers/login_via_providers.go`

### Modifying Token Claims

1. **For consent-time claims**: Edit `handlers/login_step_4_consent.go`
2. **For webhook enrichment**: Edit `handlers/webhook.go` `TokenEnrichmentEndpoint()`
3. **For service account claims**: Edit `buildServiceAccountConsentClaims()` or `handleServiceAccountEnrichment()`

### Adding New Roles

Currently roles are hardcoded. To make them dynamic:
1. Add role fetching service client to `AuthServer`
2. Fetch roles at consent time in `login_step_4_consent.go`

## Security Considerations

1. **Cookie Keys**: Default keys are in source code - **must override in production**
2. **Webhook Authentication**: The `/webhook/enrich` endpoint has no authentication (assumes network isolation with Hydra)
3. **Device Cookies**: Long-lived (15 years) - consider rotation policy
4. **Session Cookies**: Short-lived (30 minutes) for login flow

## Dependencies

External services (gRPC/Connect):
- **Profile Service**: User profile management
- **Partition Service**: Multi-tenancy (tenant/partition lookup)
- **Device Service**: Device tracking and session management
- **Notification Service**: Verification code delivery

Internal:
- **Ory Hydra**: OAuth2/OIDC authorization server
- **PostgreSQL**: Persistent storage (login events)
- **Cache (NATS/Memory)**: Login event caching
