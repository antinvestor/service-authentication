# Default Authentication App

## Overview

This is the main authentication application that serves as the Login & Consent Provider for Ory Hydra. It handles user authentication, token enrichment, and API key management.

## Directory Structure

```
apps/default/
├── cmd/
│   └── main.go              # Application entry point
│
├── config/
│   └── config.go            # Configuration struct and defaults
│
├── service/
│   ├── handlers/            # HTTP handlers (see handlers/claude.md)
│   ├── hydra/               # Hydra client (see hydra/claude.md)
│   ├── models/              # Data models
│   └── repository/          # Database repositories
│
├── static/
│   ├── css/
│   │   └── auth.css         # Authentication page styles
│   └── js/
│       └── auth.js          # Client-side validation and UX
│
├── tmpl/                    # HTML templates (Go html/template)
│   ├── auth_base.html       # Base layout template
│   ├── login.html           # Login page
│   ├── contact_verification.html  # Code verification page
│   ├── error.html           # Error page
│   └── not_found.html       # 404 page
│
├── tests/                   # Integration tests
│   ├── base_testsuite.go    # Test setup with containers
│   └── oauth2_test_client.go # OAuth2 test client
│
└── utils/                   # Utility functions
    ├── contact_validator.go # Email/phone validation
    ├── device_id.go         # Device ID context handling
    ├── encryption.go        # AES encryption utilities
    ├── generate.go          # ID generation
    └── hasher.go            # Password hashing
```

## Configuration

**File:** `config/config.go`

```go
type AuthenticationConfig struct {
    // Session settings
    SessionRememberDuration int64  `envDefault:"0"`

    // Cache configuration
    CacheName string `envDefault:"defaultCache"`
    CacheURI  string `envDefault:"mem://defaultCache"`

    // Cookie security (MUST override in production)
    SecureCookieHashKey  string `envDefault:"..."`
    SecureCookieBlockKey string `envDefault:"..."`

    // Error display
    ExposeErrors bool `envDefault:"false"`

    // Contact verification
    AuthProviderContactLoginMaxVerificationAttempts int `envDefault:"3"`

    // Google OAuth
    AuthProviderGoogleClientID     string
    AuthProviderGoogleClientSecret string
    AuthProviderGoogleRedirectURI  string
    AuthProviderGoogleScopes       string

    // Facebook OAuth
    AuthProviderMetaClientID     string
    AuthProviderMetaClientSecret string
    AuthProviderMetaRedirectURI  string
    AuthProviderMetaScopes       string
}
```

## Data Models

**File:** `service/models/models.go`

### LoginEvent

Tracks a single login attempt through the OAuth2 flow.

```go
type LoginEvent struct {
    BaseModel
    ClientID         string     // OAuth2 client ID
    LoginID          string     // Reference to Login record
    LoginChallengeID string     // Hydra login challenge
    VerificationID   string     // Verification code ID
    AccessID         string     // Access record ID
    ContactID        string     // Contact used for login
    ProfileID        string     // User's profile ID
    SessionID        string     // Device session ID
    Oauth2SessionID  string     // Hydra session ID
    DeviceID         string     // Device ID
    Properties       JSONMap    // Extra properties
    Client           string     // User agent
    IP               string     // Client IP
    Status           int        // Login status
}
```

### Login

Represents a user's login credentials/method.

```go
type Login struct {
    BaseModel
    ProfileID  string     // User's profile ID
    Source     string     // Login source (direct, google, facebook)
    Scope      string     // Granted scopes
}
```

### APIKey

API keys for service-to-service authentication.

```go
type APIKey struct {
    BaseModel
    Key        string     // The API key (hashed)
    Scope      string     // JSON array of roles
    ProfileID  string     // Owner's profile ID
}
```

## Repositories

**Directory:** `service/repository/`

### Interfaces

```go
type LoginRepository interface {
    Create(ctx context.Context, login *models.Login) error
    GetByProfileID(ctx context.Context, profileID string) (*models.Login, error)
}

type LoginEventRepository interface {
    Create(ctx context.Context, event *models.LoginEvent) error
    GetByID(ctx context.Context, id string) (*models.LoginEvent, error)
}

type APIKeyRepository interface {
    Create(ctx context.Context, key *models.APIKey) error
    GetByKey(ctx context.Context, key string) (*models.APIKey, error)
    GetByProfileID(ctx context.Context, profileID string) ([]*models.APIKey, error)
    Delete(ctx context.Context, id string) error
}
```

## Templates

Templates use Go's `html/template` with a base layout pattern.

### Base Template (`auth_base.html`)

```html
<!DOCTYPE html>
<html>
<head>
    <title>{{ template "title" .}} | Authentication</title>
    <link rel="stylesheet" href="/static/css/auth.css">
</head>
<body>
    <main>
        <h1>{{ template "title" .}}</h1>
        {{ template "subtitle" . }}
        {{ template "content" .}}
    </main>
</body>
</html>
```

### Page Templates

Each page defines:
- `title` - Page title
- `subtitle` - Optional subtitle
- `content` - Main content

## Static Assets

### CSS (`static/css/auth.css`)

Pico CSS-based styling with custom overrides:
- Max-width containers (400px) for centered forms
- Social login button styles
- Form validation styles
- Responsive design
- Dark mode support

### JavaScript (`static/js/auth.js`)

Client-side functionality:
- Form validation (email, phone, verification code)
- Auto-submit on verification code completion
- Loading states
- Error display

## Testing

Tests use Docker containers for dependencies:
- PostgreSQL
- Ory Hydra
- Profile Service
- Partition Service
- Device Service
- Notification Service

```bash
# Run tests
go test ./apps/default/... -v

# Run specific test file
go test ./apps/default/service/handlers/login_verification_test.go -v
```

## Entry Point

**File:** `cmd/main.go`

initialises:
1. Configuration from environment
2. Database connection and migrations
3. Cache manager
4. Service clients (gRPC)
5. HTTP server with handlers

## Token Claims Reference

Claims added to tokens at consent time:

| Claim | Type | Source |
|-------|------|--------|
| `tenant_id` | string | Partition Service |
| `partition_id` | string | Partition Service |
| `roles` | []string | Hardcoded `["user"]` |
| `device_id` | string | Device Service |
| `login_id` | string | Session cookie |
| `profile_id` | string | OAuth2 subject |
| `profile_contact` | string | OAuth2 subject |

## Common Tasks

### Adding a new template variable

1. Add to payload in handler:
```go
payload["my_var"] = myValue
```

2. Use in template:
```html
{{ .my_var }}
```

### Modifying login page

1. Edit `tmpl/login.html`
2. Add styles to `static/css/auth.css`
3. Add JS behavior to `static/js/auth.js`

### Adding new API endpoint

1. Add handler method to `AuthServer`
2. Register route in `handlers/routing.go`
3. Add authentication middleware if needed
