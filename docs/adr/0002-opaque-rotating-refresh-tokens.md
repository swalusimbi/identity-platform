# ADR 0002: Opaque rotating refresh tokens over JWT refresh tokens

Status: accepted

Refined by [ADR 0010](0010-operation-bound-refresh-retries.md), which distinguishes a bounded response-loss retry from other rotated-token replay.

## Context

Access tokens are stateless by design (ADR 0001), which means they cannot be revoked before expiry. Something in the session has to be revocable or a stolen credential lives for its full lifetime. The refresh token is that something, and the question was whether it should also be a JWT or server side state.

## Decision

Refresh tokens are 48 random bytes, base64url encoded, stored only as a SHA-256 hash in Postgres together with the requesting IP and user agent. Default lifetime is 7 days. Three rules define their behavior (`src/routes/auth.ts`):

- **Single use.** Redeeming a token revokes it and issues a new pair. There is never a long lived credential that stays valid after use
- **Family revocation on replay.** Redeeming a rotated token outside the operation-bound recovery path means two parties held the same token. Every refresh token the user has is revoked and both parties get signed out. The revocation reason is stored per row because the inference only holds for rotation: a token revoked by logout, self service session revocation or accepted response recovery gets presented again in normal operation, so those answer 401 without the family revocation
- **Client bound.** A refresh token is only redeemable through the credentials of the client that owns the user. Possession alone is not enough for confidential clients

Expired rows are pruned 30 days after expiry, not immediately, because replay detection depends on finding the revoked row. A daily job handles the cleanup (`src/jobs/cleanup.ts`).

## Consequences

- Logout, password reset, password change and user deactivation all revoke sessions immediately through this table
- A database read per refresh, roughly one per user per 15 minutes. That cost buys immediate revocability and is trivially indexable by token hash
- A leaked database yields no usable refresh tokens, only hashes of 256 bit random values
- The stored IP and user agent are the raw material for the sessions API on the roadmap (list active sessions, revoke one or all)

## Alternatives considered

- **JWT refresh tokens**: rejected. Revoking them requires a denylist checked on every refresh, which reintroduces exactly the server state they were supposed to avoid, with extra parsing on top
- **Non rotating opaque tokens**: rejected, a stolen token would remain valid alongside the legitimate one for up to 7 days with no theft signal. Rotation turns concurrent use into a detectable event
- **Deleting rows on revocation**: rejected, replay detection needs the tombstone. Hence the revoked flag plus 30 day retention
