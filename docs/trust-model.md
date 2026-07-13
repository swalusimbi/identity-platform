# Trust Model

Every request to the platform is made by one of seven principals. This document lists each one, what it must prove, what it may invoke, how its proof is verified and how fast it can be revoked. If a capability is not listed for a principal, that principal does not have it.

The platform serves one organization. There is no cross organization trust to model, only the boundaries between the operator, the registered applications and their users.

## The principals

| Principal | Credential | Proof presented | Revocation |
|---|---|---|---|
| Operator | Admin key | `X-Admin-Key` header | Change `ADMIN_KEY` and restart |
| Confidential client | `cl_` id + `cs_` secret | Secret on every auth call | Rotate secret or deactivate, immediate |
| Public client | `cl_` id only | PKCE verifier on OAuth exchange | Deactivate, immediate |
| User, access token | JWT (EdDSA) | Signature, issuer, expiry | None until expiry, at most 15 minutes |
| User, refresh token | Opaque 48 byte token | Possession + owning client's credentials | Immediate, single use |
| Machine, API key | `sk_` prefixed key | Key on every request | Immediate, checked per request |
| Mailbox owner | Emailed account token | Possession, single use | Consumed on use, 1 to 24 hour expiry |

## Operator

The person who runs the deployment. Authenticates with a shared secret sent as `X-Admin-Key`, compared in constant time against `ADMIN_KEY` (both sides SHA-256 hashed first to equalize lengths, `src/routes/clients.ts`).

May invoke, and is the only principal that may invoke:

- `POST /clients` register an application
- `POST /clients/:id/rotate-secret` replace a client secret
- `PATCH /clients/:id` rename, update redirect and link URLs, toggle registration, deactivate
- `POST /clients/:id/bootstrap` create the management role and invite a tenant's first admin
- `GET /clients` list applications

This is deliberately a single shared secret, not a user account. The platform currently has exactly one operator per deployment and a key in the environment is the simplest thing that is honest about that. When delegated administration lands (Phase 3 on the roadmap) this becomes a real principal with an audit trail.

The admin key never grants access to user data through the management APIs. `/users`, `/roles`, `/api-keys`, `/service-accounts`, `/sessions` and `/audit` require a user or API key principal belonging to the client in question.

## Confidential client

An application backend holding a `cl_` client id and a `cs_` client secret (32 random bytes, shown once at registration, stored as a SHA-256 hash, compared in constant time).

Must present the secret on every authentication call it relays: register, login, refresh, logout, the password and email flows and the OAuth code exchange. A wrong or missing secret is `INVALID_CLIENT` with no further detail.

What the secret proves: the request comes from the application's own backend, not from something that merely knows the public client id. That is why a refresh token can only be redeemed through the client that owns the user (`src/routes/auth.ts` checks the token's user belongs to the presenting client before rotating).

## Public client

A SPA or mobile app registered with `isPublic: true`. It has no secret because it cannot keep one. Three things bound what it can do:

- OAuth flows require PKCE with S256, the only accepted method. A code issued with a challenge is only redeemable with the matching verifier (43 to 128 characters, compared in constant time)
- Redirect URIs must be registered in advance. A client with no registered URIs cannot use OAuth at all
- Refresh tokens rotate on every use and replay revokes the whole family

A public client id is not a secret and the platform treats it as public knowledge. Nothing destructive is reachable with the id alone, which is also why emailed links are built only from registered URLs (see [ADR 0005](adr/0005-registered-email-link-urls.md)).

## User with an access token

A signed EdDSA JWT, 15 minutes by default, carrying:

| Claim | Meaning |
|---|---|
| `sub` | User id |
| `cid` | Client id, both the identity home and the audience today |
| `email` | The user's email |
| `permissions` | Flattened `resource:action` strings, wildcards allowed |
| `iss` | The deployment's issuer, required on verification |
| `iat`, `exp` | Issued at and expiry |

The token header carries `alg: EdDSA` and the published `kid`. Verification pins the algorithm to the key type so a token can never choose which key it is verified against (`src/services/token.ts`).

May invoke the management APIs (`/users`, `/roles`, `/api-keys`, `/service-accounts`, `/audit`) and `/sessions` subject to the permissions inside the token, and `POST /auth/password/change` for itself.

What it cannot prove: that it has not been revoked since issuance. Access tokens are verified offline and carry no server state, so deactivating a user or changing permissions takes effect on the next refresh, at most one access token lifetime later. That window is a documented contract, not an oversight (see [contracts/sessions-and-tokens.md](contracts/sessions-and-tokens.md)).

## User with a refresh token

An opaque token of 48 random bytes, stored only as a SHA-256 hash alongside the requesting IP and user agent. Valid 7 days by default and exactly one use:

- Redeeming it revokes it and issues a new pair
- Redeeming an already revoked token is treated as replay and revokes every refresh token the user has
- It is only redeemable through the client credentials of the application the user belongs to

Revocation is immediate because every redemption is a database check. Logout, password reset, password change and deactivation all revoke by this path. Expired rows are kept 30 days past expiry because replay detection depends on finding the revoked row.

## Machine with an API key

An `sk_` prefixed key (32 random bytes, the first 8 visible as an identifying prefix, stored as a SHA-256 hash). Carries flat scopes in the same `resource:action` vocabulary as user permissions, with the same wildcard rules.

Checked against the database on every request, so revocation (`DELETE /api-keys/:id`) is immediate. Optional expiry of 1 to 365 days. `lastUsedAt` is updated fire and forget for operator visibility.

API keys belong to a client, act for that client's silo only and are created and revoked by users holding `api-keys:write`.

## Mailbox owner with an account token

The principal behind password reset, email verification and invites: whoever controls the email inbox. The token is 32 random bytes in an emailed link, stored as a SHA-256 hash, bound to one purpose and consumed atomically on first use.

| Purpose | Lifetime |
|---|---|
| Password reset | 1 hour |
| Email verification | 24 hours |
| Invite (set first password) | 24 hours |

Every failure mode (unknown, expired, used, wrong purpose, wrong client) returns the same error, so tokens cannot be probed. Completing a reset also marks the email verified, because finishing the flow proves control of the mailbox.

## Verification paths

Consumers have two ways to verify what a principal presents:

**Local, the normal path.** Fetch the public key from `GET /.well-known/jwks.json` (cacheable for 300 seconds, stale while revalidate for a day) and verify Bearer JWTs in process. No network call per request, and the platform being down does not take verification down. This is what the SDK does and what every consumer should do for user tokens.

**Remote, `POST /auth/verify`.** The platform verifies on the consumer's behalf. It is required for API keys because they are database state rather than signatures. It also supports diagnostics, JWKS outage fallback and explicitly enabled legacy HS256 migrations. Legacy verification requires `ALLOW_LEGACY_HS256` on the platform and `allowLegacyHs256` in the SDK. The response distinguishes `valid` (the artifact is genuine and unexpired) from `authorized` (it also carries the requested permission).

## Revocation summary

How long each credential keeps working after you decide it should not:

| Credential | Window |
|---|---|
| Access token | Until expiry, at most 15 minutes by default |
| Refresh token | Zero, checked on redemption |
| API key | Zero, checked per request |
| Client secret | Zero after rotation or deactivation |
| Account token | Zero, single use and purpose bound |
| Admin key | Until the process restarts with the new value |
| Signing key | Swap takes effect on restart, old access tokens fail at most 15 minutes later (see [operations/key-rotation.md](operations/key-rotation.md)) |

The only nonzero user facing window is the access token, and everything else in the design (short TTL, offline verification, rotation on refresh) exists to make that window cheap enough to accept.
