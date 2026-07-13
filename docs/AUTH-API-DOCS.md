# Identity Platform API Reference

Base URL: `https://auth.example.com`

Every deployment self describes: the machine readable spec is served at `/openapi.json` and a browsable viewer at `/docs`. This document is the human guide over the same endpoints.

Machine-readable contract: [`docs/openapi.json`](openapi.json). This file is the human guide for common integration flows.

## Quick start

1. Register your app as a client (one-time, admin only)
2. Install the JWT verification dependency: `npm install jose`
3. Drop `auth-client.ts` into your app's `src/lib/`
4. Set env vars: `AUTH_SERVICE_URL`, `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET`, `AUTH_REDIRECT_URI`
5. Use `requireAuth` middleware on protected routes

The recommended integration path is local JWT verification with JWKS. Your app verifies Bearer JWTs locally using the public key from `/.well-known/jwks.json`, so normal protected requests do not call the identity platform every time.

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

### Auth: email/password

**POST /auth/register**

Create a new user account.

Call this from your app backend. `clientSecret` must stay server-side (public clients omit it). Returns 403 `REGISTRATION_DISABLED` for invite-only clients, provision users through `POST /users` instead.

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

// Response 200: same shape as register
```

**POST /auth/refresh**

Exchange a refresh token for a new token pair. The old refresh token is revoked by the same transaction that stores its successor.

`operationId` is a fresh random UUID for each new refresh operation. Keep it until the result is known. If the response is lost, retry the old token with the same value within the configured grace period. The platform revokes the unused successor and returns a replacement pair. A different value, an expired grace period or an already-used successor triggers replay protection and revokes all active refresh tokens for the user.

```json
// Request
{
  "refreshToken": "base64url...",
  "operationId": "f57d0d06-7f23-4a2f-9884-610f198b19f8",
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

### Account lifecycle

**POST /auth/password/forgot**

Sends a password reset email. The link points at the client's registered `passwordResetUrl`, never at request supplied URLs, so a public client id cannot be abused to send phishing links. Returns 400 `RESET_URL_NOT_CONFIGURED` when the client has no registered page, otherwise always 200 so account existence cannot be probed.

```json
// Request
{
  "email": "user@example.com",
  "clientId": "cl_...",
  "clientSecret": "cs_..."
}

// Response 200
{ "message": "If that email is registered, a reset link has been sent" }
```

The email contains `<passwordResetUrl>?token=...` valid for 1 hour.

**POST /auth/password/reset**

Completes the reset with the emailed token. Single use. Revokes all of the user's sessions and marks the email verified.

```json
// Request
{
  "token": "from-the-email-link",
  "newPassword": "min8chars",
  "clientId": "cl_...",
  "clientSecret": "cs_..."
}

// Response 200
{ "message": "Password reset" }
```

**POST /auth/password/change**

Requires `Authorization: Bearer <jwt>` of the user. Revokes all sessions on success, log in again afterwards.

```json
// Request
{
  "currentPassword": "...",
  "newPassword": "min8chars"
}

// Response 200
{ "message": "Password changed" }
```

OAuth-only accounts without a password get 400 `PASSWORD_NOT_SET`, use the reset flow to set one.

**POST /auth/email/send-verification**

Same shape as `/auth/password/forgot`. Sends a verification link (to the client's registered `emailVerifyUrl`) valid for 24 hours. Nothing is sent when the email is unknown or already verified.

**POST /auth/email/verify**

```json
// Request
{
  "token": "from-the-email-link",
  "clientId": "cl_...",
  "clientSecret": "cs_..."
}

// Response 200
{ "message": "Email verified" }
```

---

### Auth: OAuth2

**GET /auth/oauth/:provider**

Initiates OAuth flow. Redirect the user's browser here.

Query params:
- `client_id`: your app's client ID (`cl_...`)
- `redirect_uri`: where to send the user after auth (must be registered)
- `code_challenge`: PKCE S256 challenge, required for public clients, supported for confidential clients
- `code_challenge_method`: only `S256` is supported. PKCE is a pair, send both `code_challenge` and `code_challenge_method` or neither, a lone parameter is a 400
- `state`: your app's one-time value (optional, up to 512 chars). Echoed back as `state` on the callback redirect, success or error. Generate it per login attempt, store it in the user's session and reject the callback when it does not match

The platform's own state parameter is single use: a callback URL cannot be replayed, the second presentation answers 400 `STATE_ALREADY_USED`.

Expected failures during the callback redirect to your registered `redirect_uri` with a stable `error` query value (and your echoed `state`):

| `error` | Meaning |
|---|---|
| provider's own code | The provider refused, for example `access_denied` when the user cancels |
| `exchange_failed` | The code could not be exchanged with the provider |
| `profile_failed` | The provider profile could not be fetched |
| `email_unverified` | The provider account has no verified email |
| `account_mismatch` | The email is already linked to a different provider identity |
| `account_inactive` | The user exists but is deactivated |

Providers: `google`, `github`

```
Example:
GET /auth/oauth/google?client_id=cl_abc&redirect_uri=https://app.example.com/auth/callback
→ Redirects to Google consent screen
→ Google redirects to the identity platform callback
→ Identity platform redirects to https://app.example.com/auth/callback?code=xyz
```

**POST /auth/oauth/token**

Exchange the authorization code for tokens. Confidential clients call this from their backend with the client secret. Public clients send the PKCE `codeVerifier` instead. Failed client, redirect URI or PKCE checks do not consume the authorization code.

```json
// Request (confidential client)
{
  "code": "xyz...",
  "clientId": "cl_...",
  "clientSecret": "cs_...",
  "redirectUri": "https://app.example.com/auth/callback"
}

// Request (public client with PKCE)
{
  "code": "xyz...",
  "clientId": "cl_...",
  "codeVerifier": "the-43-to-128-char-verifier",
  "redirectUri": "https://app.example.com/auth/callback"
}

// Response 200: same shape as login
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
      "kid": "identity-platform-v1",
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
  audience: process.env.AUTH_CLIENT_ID,
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
  "audience": "cl_0123456789abcdef",
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
  "audience": "cl_0123456789abcdef",
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

// Service account keys include the account identity
{
  "valid": true,
  "authorized": true,
  "apiKey": {
    "clientId": "uuid",
    "name": "Worker key",
    "scopes": ["users:read"],
    "serviceAccount": {
      "id": "uuid",
      "name": "sync-worker"
    }
  }
}
```

---

### Roles & permissions (requires auth)

**GET /roles**: list roles for your client (requires `roles:read`)

**POST /roles**: create a role (requires `roles:write`)

```json
{
  "name": "editor",
  "description": "Can edit content",
  "isDefault": false,
  "permissionIds": ["uuid1", "uuid2"]
}
```

**PUT /roles/:id/permissions**: replace permissions on a role (requires `roles:write`)

```json
{ "permissionIds": ["uuid1", "uuid2", "uuid3"] }
```

**DELETE /roles/:id**: delete a role (requires `roles:write`)

**POST /roles/assign**: assign a role to a user (requires `roles:write`)

```json
{ "userId": "uuid", "roleId": "uuid" }
```

**POST /roles/revoke**: remove a role from a user (requires `roles:write`)

```json
{ "userId": "uuid", "roleId": "uuid" }
```

**GET /roles/permissions**: list your client's permissions (requires `roles:read`)

**POST /roles/permissions**: create a permission for your client (requires `roles:write`)

```json
{
  "resource": "billing",
  "action": "write",
  "description": "Create and edit invoices"
}
```

**POST /roles/permissions/bulk**: seed multiple permissions (requires `roles:write`)

```json
[
  { "resource": "meters", "action": "read" },
  { "resource": "meters", "action": "write" },
  { "resource": "meters", "action": "delete" }
]
```

---

### API keys (requires auth)

**POST /api-keys**: generate a new API key (requires `api-keys:write`)

```json
// Request
{
  "name": "Production CI/CD",
  "scopes": ["billing:read", "meters:*"],
  "expiresInDays": 90
}

// Response 201: full key shown ONCE
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

**GET /api-keys**: list keys (prefix only, requires `api-keys:read`)

**DELETE /api-keys/:id**: revoke a key (requires `api-keys:write`)

---

### Service accounts (requires auth)

Use service accounts when a workload needs a stable machine identity with role-based permissions. Plain scoped API keys remain the simpler choice for fixed one-off access.

**POST /service-accounts**: create a service account (requires `service-accounts:write`)

```json
// Request
{
  "name": "sync-worker",
  "description": "Imports directory users",
  "roleIds": ["uuid"]
}

// Response 201
{
  "id": "uuid",
  "clientId": "uuid",
  "name": "sync-worker",
  "description": "Imports directory users",
  "isActive": true,
  "roleIds": ["uuid"],
  "createdAt": "2026-07-08T...",
  "updatedAt": "2026-07-08T..."
}
```

**GET /service-accounts**: list service accounts and assigned role ids (requires `service-accounts:read`)

**PATCH /service-accounts/:id**: update `name`, `description` or `isActive` (requires `service-accounts:write`). Setting `isActive: false` immediately makes every attached key unusable.

**POST /service-accounts/:id/roles**: assign a role (requires `service-accounts:write`)

```json
{ "roleId": "uuid" }
```

**DELETE /service-accounts/:id/roles/:roleId**: revoke a role (requires `service-accounts:write`)

**POST /service-accounts/:id/api-keys**: create a key credential for the service account (requires `service-accounts:write`)

```json
// Request
{
  "name": "sync-worker-prod",
  "expiresInDays": 90
}

// Response 201: full key shown ONCE
{
  "id": "uuid",
  "serviceAccountId": "uuid",
  "name": "sync-worker-prod",
  "keyPrefix": "sk_a1b2c3d4",
  "key": "sk_a1b2c3d4_full-secret-key",
  "scopes": [],
  "expiresAt": "2026-10-06T...",
  "warning": "Store this key securely. It cannot be retrieved again."
}
```

Service account keys carry no stored scopes. On every request the platform resolves the account's current role permissions, so role changes are live and do not require key rotation.

---

### User management (requires auth)

For invite-only tenants. Works with Bearer tokens and API keys, so an app backend can provision staff server to server with a `users:write` scoped key.

**POST /users**: provision a user (requires `users:write`)

```json
// Request
{
  "email": "staff@example.com",
  "roleIds": ["uuid"],
  "sendInvite": true
}

// Response 201
{ "id": "uuid", "email": "staff@example.com", "roleIds": ["uuid"], "invited": true }
```

The invite email carries a set-password link (the registered `passwordResetUrl`, valid 24 hours). Use the returned `id` to create any app-side records for the user. Set `sendInvite: false` for accounts that only sign in through OAuth.

**GET /users**: list the client's users (requires `users:read`)

**PATCH /users/:id**: deactivate or reactivate (requires `users:write`)

```json
{ "isActive": false }
```

Deactivation blocks future logins and revokes all refresh tokens immediately. Already issued access tokens stay valid until they expire (15 minutes by default), that window is the revocation contract consumers should design for, deactivate any app-side membership at the same time.

---

### Sessions (requires a user Bearer token)

Self service: users manage their own sessions. API keys are refused with `BEARER_REQUIRED`, they have no sessions.

**GET /sessions**: the user's active sessions, newest first

```json
// Response 200
[
  {
    "id": "uuid",
    "ip": "203.0.113.7",
    "userAgent": "Mozilla/5.0 ...",
    "createdAt": "2026-07-05T12:00:00.000Z",
    "expiresAt": "2026-07-12T12:00:00.000Z"
  }
]
```

The platform cannot mark which session is the caller's own: access tokens carry no reference to the refresh token that produced them.

**DELETE /sessions/:id**: revoke one session. Another user's session id answers 404.

**DELETE /sessions**: logout everywhere

```json
// Response 200
{ "message": "All sessions revoked", "count": 3 }
```

Revocation stops refresh immediately. Already issued access tokens ride out their lifetime, the standard revocation window. A device signed out this way gets a plain 401 on its next refresh, without tripping replay detection.

---

### Audit (requires auth)

Every mutating action is recorded append only: who did what, when, from where. The full event catalog and guarantees live in [contracts/audit.md](contracts/audit.md).

**GET /audit**: the client's history, newest first (requires `audit:read`, a dedicated grant not included in the bootstrap management role)

Query parameters: `action`, `actorId`, `targetId`, `from`, `to`, `limit` (default 50, max 200) and `before` for paging.

```json
// Response 200
{
  "entries": [
    {
      "id": "uuid",
      "clientId": "uuid",
      "action": "user.login",
      "actorType": "user",
      "actorId": "uuid",
      "targetType": null,
      "targetId": null,
      "ip": "203.0.113.7",
      "userAgent": "Mozilla/5.0 ...",
      "details": { "method": "password" },
      "createdAt": "2026-07-05T12:00:00.000Z"
    }
  ],
  "nextBefore": "2026-07-05T11:58:41.221Z"
}
```

Pass `nextBefore` back as `?before=` to fetch the next older page, `null` means the history is exhausted. Rows are retained for `AUDIT_RETENTION_DAYS` (default 365).

---

### Client management (admin only)

Requires `X-Admin-Key` header.

**POST /clients**: register a new app

```json
// Request
{
  "name": "My App",
  "redirectUris": ["https://app.example.com/auth/callback"],
  "isPublic": false,
  "allowUserRegistration": true,
  "passwordResetUrl": "https://app.example.com/set-password",
  "emailVerifyUrl": "https://app.example.com/verify-email"
}

// Response 201
{
  "id": "uuid",
  "name": "My App",
  "clientId": "cl_...",
  "isPublic": false,
  "clientSecret": "cs_...",
  "warning": "Store the client secret securely."
}
```

Set `isPublic: true` for apps that cannot keep a secret (SPAs, mobile apps). Public clients get no `clientSecret`, omit it from every call and must use PKCE for OAuth flows.

**GET /clients**: list all registered clients

**POST /clients/:id/rotate-secret**: replace a client's secret

Returns the new secret once. The old secret stops working immediately, update the app's environment right away. Not available for public clients.

**PATCH /clients/:id**: update a client

```json
// Request (any subset)
{
  "name": "Renamed App",
  "redirectUris": ["https://app.example.com/cb"],
  "isActive": false,
  "allowUserRegistration": false,
  "passwordResetUrl": "https://app.example.com/set-password",
  "emailVerifyUrl": "https://app.example.com/verify-email"
}
```

Setting `isActive: false` blocks every flow for that client (login, refresh, OAuth and verification) until it is reactivated. Setting `allowUserRegistration: false` closes self registration, users are then provisioned through `POST /users`.

**POST /clients/:id/bootstrap**: set up a fresh tenant

Creates the management role (`users`, `roles`, `api-keys` and `service-accounts` permissions), invites the first admin by email and returns the created user and role. Requires `passwordResetUrl` to be registered first. Safe to think of as: one call turns a bare client into a working tenant whose admin can then mint API keys, service accounts and roles.

```json
// Request
{ "adminEmail": "admin@example.com", "roleName": "admin" }

// Response 201
{
  "user": { "id": "uuid", "email": "admin@example.com" },
  "role": { "id": "uuid", "name": "admin" },
  "permissions": ["users:read", "users:write", "..."],
  "message": "Admin invited. The emailed link sets their password."
}
```

---

## JWT payload structure

New access tokens are signed with Ed25519 / EdDSA and contain:

```json
{
  "sub": "user-uuid",
  "cid": "client-uuid",
  "aud": "cl_0123456789abcdef",
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
  "kid": "identity-platform-v1"
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

The SDK surfaces every non-OK response as `AuthApiError` carrying `status`, `code`, `details` and, on 429s, `rateLimit` with the reset time from the `X-RateLimit-*` headers. Network failures and timeouts throw `AuthTransportError` instead, so applications can distinguish "the platform refused" from "the platform is unreachable". The [getting started guide](getting-started.md) shows a shared Express error middleware built on this.

Common codes:
- `VALIDATION_ERROR`: request body failed validation (details array included)
- `EMAIL_EXISTS`: email already registered for this client
- `INVALID_CREDENTIALS`: wrong email or password
- `TOKEN_EXPIRED`: JWT has expired, use /auth/refresh
- `INVALID_REFRESH_TOKEN`: refresh token is invalid, revoked, or expired
- `INVALID_CODE`: OAuth authorization code expired or already used
- `CLIENT_MISMATCH`: client ID doesn't match the one used to start OAuth
- `INSUFFICIENT_PERMISSIONS`: user lacks required permission
- `INSUFFICIENT_SCOPE`: API key lacks required scope

---

## Rate limits

| Endpoint | Limit |
|---|---|
| POST /auth/login | 5/min per IP and account plus 30/min per IP in Redis. The sample Nginx config also applies 5 req/s |
| POST /auth/register and account-token flows | 5/min per IP in Redis |
| /auth/refresh, /auth/logout, /auth/verify and JWKS | No app-level limiter. Use the outer reverse proxy for volume control |

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
