# ADR 0001: EdDSA signatures with JWKS over a shared HMAC secret

Status: accepted

## Context

The first version signed access tokens with HS256 and a shared `JWT_SECRET`. That gave consuming apps two bad options: hold the secret themselves and verify locally, or call `POST /auth/verify` on every request. Holding an HMAC secret means every consumer can also mint valid tokens, so one compromised app forges identity for all of them. Calling the platform per request makes the platform a synchronous dependency of every protected route in every app, exactly the blast radius an identity platform must not have.

## Decision

Sign access tokens with Ed25519 (EdDSA) and publish the public key at `GET /.well-known/jwks.json` with a `kid`. Consumers verify locally with the public key and can never sign. The JWKS response is cacheable for 300 seconds with stale while revalidate for a day.

Verification pins the algorithm to the key type: a token whose header says HS256 is only ever checked against the legacy secret path, an EdDSA token only against the public key (`src/services/token.ts`). A token cannot pick which key verifies it, which closes the classic algorithm confusion attack.

Ed25519 over RSA: smaller keys, fast signing and verification and no parameter choices to get wrong.

## Consequences

- The normal request path never touches the platform. Apps fetch the key once, cache it and verify in process
- Key rotation is a swap, not an overlap, because the JWKS publishes a single key. Old tokens fail for at most one access token lifetime, 15 minutes by default. The procedure lives in [operations/key-rotation.md](../operations/key-rotation.md)
- The HS256 path survives as a pinned legacy fallback, but once asymmetric keys are configured it is off by default and accepted only when `ALLOW_LEGACY_HS256` is set, so a migrated deployment does not carry the weaker algorithm as a live verification path. Without configured keys the platform runs in a keyless development mode that signs and verifies HS256 (JWKS answers 503 `JWKS_NOT_CONFIGURED`), suitable only for trying things out
- The SDK mirrors this: it sends a token to remote verification for the legacy HS256 path only when its own `allowLegacyHs256` is set, so unmatched HS256 tokens are rejected locally and cannot amplify into platform requests
- `JWT_SECRET` remains in the environment for the legacy path and for OAuth state encryption, so it cannot be dropped yet

## Alternatives considered

- **Shared HMAC secret in every consumer**: rejected, every consumer becomes a token minter and secret rotation means redeploying everything simultaneously
- **Remote verification only**: rejected, makes platform availability a per request dependency of every app
- **RSA (RS256)**: workable, rejected for key size and the temptation of configurable padding and key length
