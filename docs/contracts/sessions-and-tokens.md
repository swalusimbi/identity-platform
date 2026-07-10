# Contract: Sessions and Tokens

What a session physically is: a short lived access token that proves identity offline and a long lived refresh token that keeps the session revocable.

## The access token

A JWT signed with EdDSA (Ed25519), 15 minutes by default (`JWT_ACCESS_EXPIRY`). Consumers verify it locally with the public key from `GET /.well-known/jwks.json` and never contact the platform on the request path.

| Claim | Contents | May consumers rely on it |
|---|---|---|
| `sub` | User id (UUID) | Yes, stable for the user's lifetime |
| `cid` | Identity silo id (internal UUID) | Yes, but do not use it as the token audience |
| `aud` | Intended application (`cl_...` client id) | Must match the consuming application's configured client id |
| `email` | User's email, lowercased | Yes |
| `permissions` | Flattened `resource:action` strings, wildcards possible | Yes, this is the authorization input |
| `iss` | The deployment's issuer (hostname of `SERVICE_URL` unless `JWT_ISSUER` overrides) | Must be checked on verification |
| `iat`, `exp` | Issued at, expiry | Must be checked on verification |
| header `kid` | The signing key id published in JWKS | Used for key selection |

**Guaranteed:** every token the platform issues carries all of these. Verification must check signature, issuer, audience and expiry. The SDK's `verifyTokenLocally` checks all four.

**`cid` and `aud` have different jobs:** `cid` identifies the user's current identity silo. `aud` identifies the application allowed to accept the token. They point at the same client record in the current topology, but consumers must not treat them as interchangeable. User pools can change the identity home without changing which application is the token recipient.

## The refresh token

Opaque, 48 random bytes, never a JWT, meaningful only to the platform. 7 days by default (`JWT_REFRESH_EXPIRY_DAYS`). Stored server side as a SHA-256 hash with the issuing IP and user agent.

Guaranteed semantics:

- **Single use.** Each redemption revokes the token and inserts its successor in one transaction. Store the newest pair, the old token is dead
- **Operation-bound response recovery.** Every refresh request carries a fresh random `operationId`. Retry an ambiguous result with the same old token and operation id. During `REFRESH_RETRY_GRACE_SECONDS`, the platform may revoke the unused successor and issue a replacement pair
- **Strict replay outside recovery.** A different operation id, an expired grace period or an already-used successor revokes every active refresh token the user has. Tokens revoked by logout, the sessions API or accepted response recovery answer a plain 401
- **Client bound.** Redemption requires the credentials of the client the user belongs to
- **Revoked by lifecycle events.** Logout, password reset, password change and deactivation each revoke immediately

The operation id is part of the proof, not a generic idempotency key. Consumers generate one random UUID per new operation and retain it until the result is known. They must serialize refresh work per stored session, replace tokens atomically and ignore stale responses. The grace path does not coordinate browser tabs or multiple backend instances.

## The revocation window

The platform's one deliberate staleness bound, stated once and referenced everywhere (the sessions API below inherits it unchanged):

> Revoking a user (deactivation, logout everywhere, role change) stops refresh immediately, but access tokens already in the wild remain valid until they expire, at most `JWT_ACCESS_EXPIRY` (15 minutes by default) later.

Consumers must treat this window as the platform's revocation guarantee and size `JWT_ACCESS_EXPIRY` to their tolerance. A consumer that cannot accept any window for a specific operation (a large funds transfer, an admin action) should re-verify remotely with `POST /auth/verify` for that operation, trading a platform round trip for immediacy.

Remote verification requires the expected `audience` in every request. The value is the consuming application's external `cl_...` client id. JWTs, plain API keys and service account keys belonging to another application return `valid: false`.

## The sessions API

A session is one refresh token row, so listing and revoking sessions is listing and revoking refresh tokens. Self service, invoked by the user themselves with their Bearer token. API keys have no sessions and are refused.

| Call | Behavior |
|---|---|
| `GET /sessions` | The user's active sessions: id, ip, user agent, created and expiry times. Never the token itself or its hash |
| `DELETE /sessions/:id` | Revoke one session. Another user's session id answers 404, indistinguishable from nonexistent |
| `DELETE /sessions` | Logout everywhere: revoke every session the user has, response carries the count |

What the platform does not tell you: which listed session is the one making the request. An access token carries no reference to the refresh token that produced it, so the caller cannot be matched to a row. Clients that need "sign out other devices" revoke everything and refresh with their own stored token, or revoke selectively by ip and age shown in the listing.

Revoking a session stops its refresh immediately. An access token already issued from it rides out the revocation window above, this API adds no new semantics to that.

## What consumers may assume

- `expiresIn` in every token response is the access token lifetime in seconds (900 by default), suitable for scheduling refresh
- Access tokens verify offline for their whole lifetime even if the platform is down. Sessions outlive short platform outages, refresh does not
- JWKS responses are cacheable for 300 seconds and safe to serve stale for a day while revalidating. The SDK refetches when it sees an unknown `kid`, which is what makes key rotation invisible (see [operations/key-rotation.md](../operations/key-rotation.md))
- Expired refresh rows are pruned 30 days after expiry. Nothing a consumer holds is affected, replay detection inside the platform depends on that retention

## When this can change

Claim names, the audience rule, the single use rule, the operation-bound retry rule and the revocation window definition are stable API. The default lifetimes (15 minutes and 7 days) and the retry grace are per deployment configuration, so consumers should read `expiresIn` instead of hard coding 900.
