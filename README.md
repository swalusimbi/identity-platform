# Identity Platform

> Provide secure identity and access management for any application inside an organization.

An identity and access management platform for teams that run more than one application. Register each app as a client, integrate through contracts and let the platform own authentication, authorization, token issuance and the account lifecycle. Running in production, serving multiple applications.

Built with Node.js, Express 5, TypeScript, PostgreSQL (Drizzle ORM) and Redis.

## Why

Every application eventually needs login, and most teams rebuild it badly under deadline pressure: passwords hashed with whatever the framework suggests, tokens that can't be revoked, resets bolted on later, permissions scattered through route handlers. The second application copies the first one's mistakes and doubles the attack surface.

This platform takes the position that identity is infrastructure. One service establishes who someone is, proves it with verifiable tokens and answers what they may do. Applications integrate against documented contracts instead of owning auth code. When an engineering team says "we need users to sign in", the answer is not a snippet to copy, it is "integrate with the platform".

## Philosophy

- **Identity is infrastructure.** When identity is down everything is down, so the platform is built and operated like the highest blast radius service it is
- **Platforms are defined by contracts, not features.** Every capability answers who may invoke it, what they must prove and what consumers may rely on afterwards
- **Centralize issuance, decentralize verification, bound revocation.** Only the platform mints identity, consumers verify locally through JWKS and revocation has a documented staleness window
- **Operational guarantees are product features.** Fail open or fail closed is a product decision, not an implementation detail
- **Depth is opt in, the simple case stays simple.** One application integrates in minutes and never sees the machinery it doesn't use
- **Everything auditable, secrets never shown twice, least privilege by default**

## Features

- **Email and password authentication** with argon2id hashing and timing attack protection
- **Account lifecycle**: password reset, email verification and password change with single use emailed tokens and a pluggable mailer (SMTP or console). Email links are built only from URLs registered on the client, never from request input
- **Invite-only tenants**: per client registration toggle, a user management API (provision with emailed invites, list, deactivate) and a one-call tenant bootstrap that creates the management role and invites the first admin
- **OAuth2 sign in** via Google and GitHub with encrypted state and single use authorization codes
- **Public clients with PKCE** (S256) so SPAs and mobile apps can integrate without a client secret, alongside confidential clients with secrets, rotation and deactivation
- **JWT access tokens** signed with EdDSA (Ed25519) and verifiable locally by any consumer through JWKS, no network round trip per request
- **Opaque refresh tokens** with rotation, family revocation on replay and automatic pruning
- **Self service sessions**: users list their active sessions with device metadata and revoke one or all with their own Bearer token
- **Multi application by design**: every application registers as a client and gets its own isolated users, roles, permissions, service accounts and API keys
- **Role based access control** with per client roles, per client permission catalogs and wildcard support (`users:*`)
- **Machine access** through plain scoped API keys for simple scripts and service accounts for role-bearing workloads. Keys are shown once and stored only as hashes
- **Admin console** at `/admin` over the same management APIs used by scripts and integrations
- **Append only audit log** recording who did what, when, from where across every mutating action, readable per client behind a dedicated `audit:read` grant
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
│                      Identity Platform                      │
│                                                             │
│   /auth/*          login, register, refresh, logout         │
│   /auth/oauth/*    Google and GitHub flows                  │
│   /auth/verify     remote verification (API keys, legacy)   │
│   /sessions        list and revoke own sessions             │
│   /users, /roles, /api-keys, /service-accounts              │
│   /clients, /audit                             management   │
│   /admin                                      admin console  │
│   /.well-known/jwks.json         public signing key         │
│                                                             │
│        PostgreSQL                    Redis                  │
│   users, clients, roles,      auth codes, rate limits       │
│   permissions, tokens, keys                                 │
└─────────────────────────────────────────────────────────────┘
```

The normal request path never touches the platform. Apps fetch the public key from JWKS once, cache it and verify Bearer tokens in process. The platform is only called for logins, refreshes, OAuth exchanges and API key checks.

### Token model

| Token | Format | Lifetime | Storage |
|---|---|---|---|
| Access token | JWT (EdDSA) | 15 minutes (configurable) | Nowhere, stateless |
| Refresh token | Opaque random | 7 days (configurable) | SHA-256 hash in Postgres |
| OAuth auth code | Opaque random | 60 seconds, single use | SHA-256 hash in Redis |
| API key | Opaque with prefix | Optional expiry | SHA-256 hash in Postgres |

Access tokens carry the user id, client id, email and a flattened permission list (`["users:read", "billing:write"]`), so consumers authorize without any extra lookup.

Plain API keys carry immutable scopes. Service account keys carry no scopes, authenticate as the account and resolve the account's role permissions on each request.

## Design decisions

- **Per client user silos.** The same email under two clients is two unrelated accounts, each application is fully self contained today. Shared identity across applications (user pools) is a designed extension point on the roadmap: sharing will be opt in per client and standalone stays the default
- **Asymmetric signing with a JWKS endpoint.** Consumers verify tokens with the public key and never hold a shared secret. A symmetric HS256 fallback exists for legacy tokens and is pinned to its own verification path
- **Refresh token rotation with family revocation.** Every refresh issues a new token and revokes the old one. Reusing a revoked token is treated as a replay attack and revokes all of the user's tokens
- **Permissions are baked into the access token.** Role changes take effect on the next refresh (at most one access token lifetime later) in exchange for zero per request lookups
- **Service accounts separate credential from grant.** Rotate a service account key without changing permissions and change service account roles without reissuing keys
- **Secrets are never stored or shown twice.** Client secrets, API keys and refresh tokens are hashed at rest. Creation responses are the only time the plaintext exists
- **OAuth state is encrypted and expiring.** The state parameter is AES-256-GCM encrypted, carries a nonce and an issued at timestamp and is rejected after 10 minutes
- **Rate limiting fails open.** If Redis is unavailable the platform keeps serving logins rather than locking everyone out. Login is limited per IP and account in two layers, so many users behind one NAT don't starve each other
- **Emailed links come from registered configuration.** Reset and verification links are built from the client's registered URLs, set only through the admin API. Request input never chooses a link target, so a public client id can't be turned into a phishing relay
- **Deactivation has a bounded tail.** Deactivating a user blocks logins and revokes refresh tokens immediately, while already issued access tokens ride out their TTL (15 minutes by default). Consumers should treat that window as the revocation contract
- **Two client types.** Confidential clients authenticate every call with their secret. Public clients (SPAs, mobile apps) have no secret, must prove possession of the PKCE verifier on OAuth exchanges and rely on refresh token rotation with family revocation, the standard model for browser based apps

## Roadmap

The platform grows in capability layers, each building on the one below. Phase 1 (identity foundation) and Phase 2 (platform foundation) are shipped, Phase 3 (enterprise identity) is designed. See [ROADMAP.md](ROADMAP.md) for the full picture including where the model deliberately evolves.

## Documentation

The docs are organized by the question they answer:

| Question | Where |
|---|---|
| Who can invoke what, proving what | [docs/trust-model.md](docs/trust-model.md) |
| What may my app rely on | [docs/contracts/](docs/contracts/README.md) |
| Why is it built this way | [docs/adr/](docs/adr/README.md) |
| How do I operate it | [docs/operations/](docs/operations/availability.md) |
| What is it defended against | [docs/threat-model.md](docs/threat-model.md) |
| What is the machine-readable API contract | [docs/openapi.json](docs/openapi.json) |
| What are the exact endpoints | live at `/docs` on any deployment, spec at [docs/openapi.json](docs/openapi.json), guide at [docs/AUTH-API-DOCS.md](docs/AUTH-API-DOCS.md) |
| How do I verify tokens myself | [docs/AUTH-JWKS-INTEGRATION.md](docs/AUTH-JWKS-INTEGRATION.md) |
| What does this term mean here | [docs/glossary.md](docs/glossary.md) |

Security reports go through [SECURITY.md](SECURITY.md).

## Project structure

```
src/
  routes/        HTTP handlers: auth, account, oauth, verify, roles, users,
                 api keys, service accounts, clients, jwks
  services/      the logic: tokens, sessions, oauth, passwords, mail
  middleware/    authentication, permission checks, rate limiting
  db/            Drizzle schema, connections, first run seed
  jobs/          daily pruning of stale tokens
  utils/         zod validated environment, error handling
sdk/             drop in client SDK for consuming apps
docs/            trust model, contracts, ADRs, operations runbooks,
                 threat model, glossary, API reference
drizzle/         generated SQL migrations
tests/           integration test suite (vitest + supertest)
nginx/           reverse proxy sample with rate limiting
```

## Getting started

### Prerequisites

- Node.js 20+
- PostgreSQL 14+
- Redis 6+

### Setup

```bash
git clone <repo-url> && cd identity-platform
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

See [docs/openapi.json](docs/openapi.json) for the machine-readable API contract, [docs/AUTH-API-DOCS.md](docs/AUTH-API-DOCS.md) for the human API guide and [docs/AUTH-JWKS-INTEGRATION.md](docs/AUTH-JWKS-INTEGRATION.md) for verifying tokens without the SDK.

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DATABASE_URL` | yes | | PostgreSQL connection string |
| `REDIS_URL` | no | `redis://localhost:6379/3` | Redis connection string |
| `JWT_SECRET` | yes | | Legacy HS256 verification and OAuth state encryption (32+ chars) |
| `JWT_PRIVATE_KEY` | yes* | | Ed25519 private key (PKCS8 PEM, `\n` escaped) |
| `JWT_PUBLIC_KEY` | yes* | | Ed25519 public key (SPKI PEM) |
| `JWT_KEY_ID` | no | `identity-platform-v1` | `kid` published in JWKS |
| `JWT_ISSUER` | no | `SERVICE_URL` hostname | `iss` claim in tokens |
| `JWT_ACCESS_EXPIRY` | no | `15m` | Access token lifetime |
| `JWT_REFRESH_EXPIRY_DAYS` | no | `7` | Refresh token lifetime |
| `ADMIN_KEY` | yes | | Shared secret for client registration |
| `AUDIT_RETENTION_DAYS` | no | `365` | Audit rows older than this are pruned daily |
| `SERVICE_URL` | no | `http://localhost:5300` | Public URL, used for OAuth callbacks and the issuer |
| `CORS_ORIGINS` | no | none in production | Comma separated browser origins, `*.example.com` allows subdomains |
| `MAIL_PROVIDER` | no | `console` | `console` logs mails, `smtp` delivers them |
| `SMTP_URL` | when smtp | | `smtp://user:pass@host:port` connection string |
| `MAIL_FROM` | no | `Auth Service <no-reply@localhost>` | Sender for outgoing mail |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | no | | Enables Google OAuth |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | no | | Enables GitHub OAuth |
| `PORT` | no | `5300` | Listen port |

\* The key pair is optional as a pair. Without it the platform falls back to HS256 signing and JWKS is disabled, which is only suitable for trying things out.

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
- Set `CORS_ORIGINS` if browsers call the platform directly. Server to server integrations do not need it. Public clients used from a browser require it.

### Rotating the signing key

JWKS publishes a single key, so rotation is a swap rather than an overlap:

1. Generate a new Ed25519 pair and update `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY` and `JWT_KEY_ID` (bump the id, for example `identity-platform-v2`)
2. Restart the service

Access tokens signed by the old key fail verification for at most one access token lifetime (15 minutes by default). Consumers using the SDK or any auto refreshing client recover transparently: the failed request triggers a refresh and the refresh returns a token signed by the new key. Refresh tokens are opaque and unaffected. Rotate during low traffic if that brief window of forced refreshes matters to you.

If the private key may have been exposed, also revoke active sessions:

```sql
UPDATE refresh_tokens SET revoked = true WHERE revoked = false;
```

## License

[MIT](LICENSE)
