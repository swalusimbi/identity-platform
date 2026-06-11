# Auth Service

A standalone authentication and authorization microservice. Register it once, point any number of applications at it and let each one authenticate users, issue tokens and enforce permissions without owning any auth code.

Built with Node.js, Express 5, TypeScript, PostgreSQL (Drizzle ORM) and Redis.

## Features

- **Email and password authentication** with argon2id hashing and timing attack protection
- **Account lifecycle**: password reset, email verification and password change with single use emailed tokens and a pluggable mailer (SMTP or console)
- **OAuth2 sign in** via Google and GitHub with encrypted state and single use authorization codes
- **JWT access tokens** signed with EdDSA (Ed25519) and verifiable locally by any consumer through JWKS, no network round trip per request
- **Opaque refresh tokens** with rotation, family revocation on replay and automatic pruning
- **Multi tenant by design**: every application registers as a client and gets its own isolated users, roles, permissions and API keys
- **Role based access control** with per client roles, per client permission catalogs and wildcard support (`users:*`)
- **API keys** for machine to machine access, shown once and stored only as hashes
- **Redis backed rate limiting** that fails open if Redis is down
- **Drop in TypeScript SDK** with Express middleware for consuming apps

## Architecture

```
┌─────────────┐        ┌─────────────┐        ┌─────────────┐
│   App A     │        │   App B     │        │   App C     │
│  (backend)  │        │  (backend)  │        │  (backend)  │
└──────┬──────┘        └──────┬──────┘        └──────┬──────┘
       │ login / refresh / oauth code exchange       │
       │ (client credentials, server to server)      │
       ▼                      ▼                      ▼
┌─────────────────────────────────────────────────────────────┐
│                        Auth Service                         │
│                                                             │
│   /auth/*          login, register, refresh, logout         │
│   /auth/oauth/*    Google and GitHub flows                  │
│   /auth/verify     remote verification (API keys, legacy)   │
│   /roles, /api-keys, /clients    management APIs            │
│   /.well-known/jwks.json         public signing key         │
│                                                             │
│        PostgreSQL                    Redis                  │
│   users, clients, roles,      auth codes, rate limits       │
│   permissions, tokens, keys                                 │
└─────────────────────────────────────────────────────────────┘
```

The normal request path never touches the auth service. Apps fetch the public key from JWKS once, cache it and verify Bearer tokens in process. The service is only called for logins, refreshes, OAuth exchanges and API key checks.

### Token model

| Token | Format | Lifetime | Storage |
|---|---|---|---|
| Access token | JWT (EdDSA) | 15 minutes (configurable) | Nowhere, stateless |
| Refresh token | Opaque random | 7 days (configurable) | SHA-256 hash in Postgres |
| OAuth auth code | Opaque random | 60 seconds, single use | SHA-256 hash in Redis |
| API key | Opaque with prefix | Optional expiry | SHA-256 hash in Postgres |

Access tokens carry the user id, client id, email and a flattened permission list (`["users:read", "billing:write"]`), so consumers authorize without any extra lookup.

## Design decisions

- **Per client user silos.** The same email under two clients is two unrelated accounts. Each application is fully self contained, there is no cross app identity or SSO. This is intentional.
- **Asymmetric signing with a JWKS endpoint.** Consumers verify tokens with the public key and never hold a shared secret. A symmetric HS256 fallback exists for legacy tokens and is pinned to its own verification path.
- **Refresh token rotation with family revocation.** Every refresh issues a new token and revokes the old one. Reusing a revoked token is treated as a replay attack and revokes all of the user's tokens.
- **Permissions are baked into the access token.** Role changes take effect on the next refresh (at most one access token lifetime later) in exchange for zero per request lookups.
- **Secrets are never stored or shown twice.** Client secrets, API keys and refresh tokens are hashed at rest. Creation responses are the only time the plaintext exists.
- **OAuth state is encrypted and expiring.** The state parameter is AES-256-GCM encrypted, carries a nonce and an issued at timestamp and is rejected after 10 minutes.
- **Rate limiting fails open.** If Redis is unavailable the service keeps serving logins rather than locking everyone out.

## Project structure

```
src/
  app.ts                 Express app (routes, middleware, health)
  index.ts               Server bootstrap (Redis connect, cleanup job, listen)
  db/
    schema.ts            Drizzle schema: clients, users, roles, permissions,
                         role_permissions, user_roles, refresh_tokens, api_keys
    index.ts             Postgres connection pool
    redis.ts             Redis client
    seed.ts              First run seed (client, roles, permissions, admin user)
  routes/
    auth.ts              register, login, refresh, logout
    account.ts           password reset, email verification, password change
    oauth.ts             provider initiation, callback, code exchange
    verify.ts            POST /auth/verify for remote verification
    roles.ts             roles and permissions CRUD, assignment
    apiKeys.ts           API key create, list, revoke
    clients.ts           client registration (admin key protected)
    jwks.ts              /.well-known/jwks.json
  services/
    token.ts             JWT signing and verification, refresh token generation
    session.ts           client credential checks, permission loading,
                         session issuance
    oauth.ts             provider configs, state encryption, auth codes
    accountToken.ts      single use reset and verification tokens
    mailer.ts            console, smtp and memory mail providers
    password.ts          argon2id hashing
    apiKey.ts            key generation and scope matching
  middleware/
    authenticate.ts      Bearer JWT and ApiKey authentication
    authorize.ts         requirePermission / requireAnyPermission
    rateLimit.ts         Redis fixed window rate limiter
  jobs/
    cleanup.ts           daily pruning of stale refresh and account tokens
  utils/
    env.ts               zod validated environment
    errors.ts            AppError and the global error handler
sdk/
  auth-client.ts         drop in client SDK for consuming apps
docs/
  AUTH-API-DOCS.md       full API reference
  AUTH-JWKS-INTEGRATION.md  JWKS integration guide for consumers
drizzle/                 generated SQL migrations
tests/                   integration test suite (vitest + supertest)
nginx/auth.conf          reverse proxy sample with rate limiting
```

## Getting started

### Prerequisites

- Node.js 20+
- PostgreSQL 14+
- Redis 6+

### Setup

```bash
git clone <repo-url> && cd auth-service
npm install

# Configure
cp .env.example .env
# Fill in DATABASE_URL, REDIS_URL, JWT_SECRET, ADMIN_KEY and the JWT keys:
#   openssl genpkey -algorithm Ed25519 -out jwt-private.pem
#   openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem

# Create the schema
npm run db:migrate

# Seed the first client, roles and admin user (prints credentials once)
npx tsx src/db/seed.ts

# Run
npm run dev          # development with reload
npm run build && npm start   # production
```

### Registering an application

```bash
curl -X POST https://auth.example.com/clients \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "My App", "redirectUris": ["https://app.example.com/auth/callback"]}'
```

The response contains the `clientId` and `clientSecret` your app uses for every auth call. The secret is shown once.

### Integrating an application

Copy `sdk/auth-client.ts` into your app and create a client:

```ts
import { createAuthClient, requirePermission } from "./lib/auth-client";

const auth = createAuthClient({
  serviceUrl: "https://auth.example.com",
  clientId: process.env.AUTH_CLIENT_ID!,
  clientSecret: process.env.AUTH_CLIENT_SECRET!,
  redirectUri: "https://app.example.com/auth/callback",
});

app.get("/dashboard", auth.requireAuth, handler);
app.delete("/users/:id", auth.requireAuth, requirePermission("users:delete"), handler);
```

See [docs/AUTH-API-DOCS.md](docs/AUTH-API-DOCS.md) for the full API and [docs/AUTH-JWKS-INTEGRATION.md](docs/AUTH-JWKS-INTEGRATION.md) for verifying tokens without the SDK.

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DATABASE_URL` | yes | | PostgreSQL connection string |
| `REDIS_URL` | no | `redis://localhost:6379/3` | Redis connection string |
| `JWT_SECRET` | yes | | Legacy HS256 verification and OAuth state encryption (32+ chars) |
| `JWT_PRIVATE_KEY` | yes* | | Ed25519 private key (PKCS8 PEM, `\n` escaped) |
| `JWT_PUBLIC_KEY` | yes* | | Ed25519 public key (SPKI PEM) |
| `JWT_KEY_ID` | no | `auth-service-v1` | `kid` published in JWKS |
| `JWT_ISSUER` | no | `SERVICE_URL` hostname | `iss` claim in tokens |
| `JWT_ACCESS_EXPIRY` | no | `15m` | Access token lifetime |
| `JWT_REFRESH_EXPIRY_DAYS` | no | `7` | Refresh token lifetime |
| `ADMIN_KEY` | yes | | Shared secret for client registration |
| `SERVICE_URL` | no | `http://localhost:5300` | Public URL, used for OAuth callbacks and the issuer |
| `CORS_ORIGINS` | no | none in production | Comma separated browser origins, `*.example.com` allows subdomains |
| `MAIL_PROVIDER` | no | `console` | `console` logs mails, `smtp` delivers them |
| `SMTP_URL` | when smtp | | `smtp://user:pass@host:port` connection string |
| `MAIL_FROM` | no | `Auth Service <no-reply@localhost>` | Sender for outgoing mail |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | no | | Enables Google OAuth |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | no | | Enables GitHub OAuth |
| `PORT` | no | `5300` | Listen port |

\* The key pair is optional as a pair. Without it the service falls back to HS256 signing and JWKS is disabled, which is only suitable for trying things out.

## Testing

The integration suite runs against real Postgres and Redis instances.

```bash
cp .env.test.example .env.test   # point it at a disposable database
npm test
```

The global setup pushes the schema, truncates all tables and flushes the configured Redis DB, so never point `.env.test` at data you care about. The runner refuses database names that do not contain `test`.

## Deployment notes

- Run behind a reverse proxy with TLS. A sample nginx config with rate limiting is in [nginx/auth.conf](nginx/auth.conf). The app sets `trust proxy 1`.
- `GET /health` reports Redis and database connectivity and returns 503 when either is down.
- Refresh tokens are pruned automatically 30 days after expiry.
- Set `CORS_ORIGINS` if browsers call the service directly. Server to server integrations do not need it.

## License

[MIT](LICENSE)
