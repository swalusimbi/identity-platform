# Auth Service — API Reference

Base URL: `https://auth.example.com`

## Quick start

1. Register your app as a client (one-time, admin only)
2. Install the JWT verification dependency: `npm install jose`
3. Drop `auth-client.ts` into your app's `src/lib/`
4. Set env vars: `AUTH_SERVICE_URL`, `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET`, `AUTH_REDIRECT_URI`
5. Use `requireAuth` middleware on protected routes

The recommended integration path is local JWT verification with JWKS. Your app verifies Bearer JWTs locally using the public key from `/.well-known/jwks.json`, so normal protected requests do not call the auth service every time.

---

## Authentication

All protected endpoints require one of:

- **Bearer token**: `Authorization: Bearer <jwt>`
- **API key**: `Authorization: ApiKey <sk_...>`

---

## Endpoints

### Health

**GET /health**

Returns service status. No auth required.

```
Response: { "status": "ok", "redis": "ok", "database": "ok" }
```

---

### Auth — email/password

**POST /auth/register**

Create a new user account.

Call this from your app backend. `clientSecret` must stay server-side.

```json
// Request
{
  "email": "user@example.com",
  "password": "min8chars",
  "clientId": "cl_...",
  "clientSecret": "cs_..."
}

// Response 201
{
  "user": { "id": "uuid", "email": "user@example.com" },
  "accessToken": "eyJ...",
  "refreshToken": "base64url...",
  "expiresIn": 900
}
```

**POST /auth/login**

```json
// Request
{
  "email": "user@example.com",
  "password": "...",
  "clientId": "cl_...",
  "clientSecret": "cs_..."
}

// Response 200 — same shape as register
```

**POST /auth/refresh**

Exchange a refresh token for a new token pair. The old refresh token is revoked (rotation). If a revoked token is reused, ALL tokens for that user are revoked (replay attack protection).

```json
// Request
{
  "refreshToken": "base64url...",
  "clientId": "cl_...",
  "clientSecret": "cs_..."
}

// Response 200
{
  "accessToken": "eyJ...",
  "refreshToken": "new-base64url...",
  "expiresIn": 900
}
```

**POST /auth/logout**

Revoke a refresh token.

```json
// Request
{
  "refreshToken": "base64url...",
  "clientId": "cl_...",
  "clientSecret": "cs_..."
}

// Response 200
{ "message": "Logged out" }
```

---

### Auth — OAuth2

**GET /auth/oauth/:provider**

Initiates OAuth flow. Redirect the user's browser here.

Query params:
- `client_id` — your app's client ID (`cl_...`)
- `redirect_uri` — where to send the user after auth (must be registered)

Providers: `google`, `github`

```
Example:
GET /auth/oauth/google?client_id=cl_abc&redirect_uri=https://app.example.com/auth/callback
→ Redirects to Google consent screen
→ Google redirects to auth service callback
→ Auth service redirects to https://app.example.com/auth/callback?code=xyz
```

**POST /auth/oauth/token**

Exchange the authorization code for tokens. Call this from your backend (never from the browser — it requires your client secret).

```json
// Request
{
  "code": "xyz...",
  "clientId": "cl_...",
  "clientSecret": "cs_...",
  "redirectUri": "https://app.example.com/auth/callback"
}

// Response 200 — same shape as login
{
  "user": { "id": "uuid", "email": "user@example.com" },
  "accessToken": "eyJ...",
  "refreshToken": "base64url...",
  "expiresIn": 900
}
```

---

### Token verification

### Local JWT verification with JWKS

**GET /.well-known/jwks.json**

Returns the public signing key used by apps to verify Bearer JWTs locally.

```json
{
  "keys": [
    {
      "crv": "Ed25519",
      "x": "...",
      "kty": "OKP",
      "kid": "auth-service-v1",
      "alg": "EdDSA",
      "use": "sig"
    }
  ]
}
```

Use this endpoint through a JWKS-aware JWT library such as `jose`.

```ts
import { createRemoteJWKSet, jwtVerify } from "jose";

const jwks = createRemoteJWKSet(
  new URL("https://auth.example.com/.well-known/jwks.json")
);

const { payload } = await jwtVerify(accessToken, jwks, {
  issuer: "auth.example.com",
});
```

The public keys are cacheable. A typical app should cache them in-process and only refetch when the cache is cold or the token references an unknown `kid`.

**POST /auth/verify**

Central verification endpoint.

For Bearer JWTs, prefer local JWKS verification above. Keep this endpoint for:

- API key verification
- Legacy token fallback
- Diagnostics
- Cases where you intentionally want centralized introspection

```json
// Verify a JWT
{
  "token": "eyJ...",
  "requiredPermission": "users:delete"  // optional
}

// Response
{
  "valid": true,
  "authorized": true,
  "user": {
    "id": "uuid",
    "clientId": "uuid",
    "email": "user@example.com",
    "permissions": ["users:read", "users:write"]
  }
}

// Or verify an API key
{
  "apiKey": "sk_a1b2c3d4_...",
  "requiredPermission": "billing:read"
}

// Response
{
  "valid": true,
  "authorized": true,
  "apiKey": {
    "clientId": "uuid",
    "name": "Production key",
    "scopes": ["billing:*"]
  }
}
```

---

### Roles & permissions (requires auth)

**GET /roles** — list roles for your client (requires `roles:read`)

**POST /roles** — create a role (requires `roles:write`)

```json
{
  "name": "editor",
  "description": "Can edit content",
  "isDefault": false,
  "permissionIds": ["uuid1", "uuid2"]
}
```

**PUT /roles/:id/permissions** — replace permissions on a role (requires `roles:write`)

```json
{ "permissionIds": ["uuid1", "uuid2", "uuid3"] }
```

**DELETE /roles/:id** — delete a role (requires `roles:write`)

**POST /roles/assign** — assign a role to a user (requires `roles:write`)

```json
{ "userId": "uuid", "roleId": "uuid" }
```

**POST /roles/revoke** — remove a role from a user (requires `roles:write`)

```json
{ "userId": "uuid", "roleId": "uuid" }
```

**GET /roles/permissions** — list your client's permissions (requires `roles:read`)

**POST /roles/permissions** — create a permission for your client (requires `roles:write`)

```json
{
  "resource": "billing",
  "action": "write",
  "description": "Create and edit invoices"
}
```

**POST /roles/permissions/bulk** — seed multiple permissions (requires `roles:write`)

```json
[
  { "resource": "meters", "action": "read" },
  { "resource": "meters", "action": "write" },
  { "resource": "meters", "action": "delete" }
]
```

---

### API keys (requires auth)

**POST /api-keys** — generate a new API key (requires `api-keys:write`)

```json
// Request
{
  "name": "Production CI/CD",
  "scopes": ["billing:read", "meters:*"],
  "expiresInDays": 90
}

// Response 201 — full key shown ONCE
{
  "id": "uuid",
  "name": "Production CI/CD",
  "keyPrefix": "sk_a1b2c3d4",
  "key": "sk_a1b2c3d4_full-secret-key",
  "scopes": ["billing:read", "meters:*"],
  "expiresAt": "2026-07-20T...",
  "warning": "Store this key securely. It cannot be retrieved again."
}
```

**GET /api-keys** — list keys (prefix only, requires `api-keys:read`)

**DELETE /api-keys/:id** — revoke a key (requires `api-keys:write`)

---

### Client management (admin only)

Requires `X-Admin-Key` header.

**POST /clients** — register a new app

```json
// Request
{
  "name": "My App",
  "redirectUris": ["https://app.example.com/auth/callback"]
}

// Response 201
{
  "id": "uuid",
  "name": "My App",
  "clientId": "cl_...",
  "clientSecret": "cs_...",
  "warning": "Store the client secret securely."
}
```

**GET /clients** — list all registered clients

---

## JWT payload structure

New access tokens are signed with Ed25519 / EdDSA and contain:

```json
{
  "sub": "user-uuid",
  "cid": "client-uuid",
  "email": "user@example.com",
  "permissions": ["users:read", "billing:write"],
  "iss": "auth.example.com",
  "iat": 1719000000,
  "exp": 1719000900
}
```

JWT header:

```json
{
  "alg": "EdDSA",
  "kid": "auth-service-v1"
}
```

---

## Error responses

All errors follow this shape:

```json
{
  "error": "Human-readable message",
  "code": "MACHINE_READABLE_CODE",
  "details": []  // only for validation errors
}
```

Common codes:
- `VALIDATION_ERROR` — request body failed validation (details array included)
- `EMAIL_EXISTS` — email already registered for this client
- `INVALID_CREDENTIALS` — wrong email or password
- `TOKEN_EXPIRED` — JWT has expired, use /auth/refresh
- `INVALID_REFRESH_TOKEN` — refresh token is invalid, revoked, or expired
- `INVALID_CODE` — OAuth authorization code expired or already used
- `CLIENT_MISMATCH` — client ID doesn't match the one used to start OAuth
- `INSUFFICIENT_PERMISSIONS` — user lacks required permission
- `INSUFFICIENT_SCOPE` — API key lacks required scope

---

## Rate limits

| Endpoint | Limit |
|---|---|
| POST /auth/login, /auth/register | 5 req/s per IP (Nginx) + 5/min per IP (Redis) |
| All /auth/* | 30 req/s per IP (Nginx) + 20/15min per IP (Redis) |
| Authenticated endpoints | 100/min per user or API key |

Rate limit headers included: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

---

## Integration checklist

1. Register your app: `POST /clients` with admin key
2. Save `clientId` and `clientSecret`
3. Add redirect URIs for OAuth if using it
4. Install `jose`
5. Set env vars in your app
6. Drop `auth-client.ts` into your project
7. Seed app-specific permissions: `POST /roles/permissions/bulk`
8. Create app-specific roles: `POST /roles`
9. Use `requireAuth` and `requirePermission` middleware on your routes
10. Use `/auth/verify` only for API keys or explicit fallback cases
