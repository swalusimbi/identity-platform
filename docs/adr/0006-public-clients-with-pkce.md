# ADR 0006: Public clients with PKCE over requiring a backend for frontend

Status: accepted

## Context

SPAs and mobile apps cannot keep a client secret. Anything shipped to a browser or unpacked from an app store is public. The platform had two honest options: refuse such apps direct integration and require every one of them to stand up a backend for frontend that holds a secret, or support secretless clients with a containment story.

## Decision

Support public clients as a first class type. `isPublic: true` at registration means no secret is generated and none is ever expected. Containment comes from three mechanisms instead of one secret:

- **PKCE, S256 only** (RFC 7636). OAuth initiation for a public client refuses to start without a `code_challenge` (`PKCE_REQUIRED`). The authorization code is bound to the challenge and only redeemable with the matching verifier, 43 to 128 characters, compared in constant time. `plain` is not accepted
- **Registered redirect URIs.** The code is only ever sent to a URI registered by the operator. A client with no registered URIs cannot use OAuth at all
- **Short, single use codes.** Authorization codes live 60 seconds in Redis, stored as SHA-256 hashes and consumed atomically by a Lua get and delete, so an intercepted code is nearly always already dead

Refresh token rotation with family revocation (ADR 0002) covers the session after sign in: the one credential a public client stores is single use and theft is detectable.

## Consequences

- A React SPA or a mobile app integrates directly with no server component, which is the "simple case stays simple" principle applied to client types
- The public client id is treated as public knowledge everywhere else in the design. ADR 0005 (registered email link URLs) exists because this assumption was tested and found violated
- Confidential clients remain the default and the stronger option. A backend that can hold a secret should

## Alternatives considered

- **Require a BFF for every browser app**: rejected, it taxes every small frontend with a server it did not need and teams route around such taxes with worse improvisations
- **PKCE plain method for convenience**: rejected, S256 costs one hash and removes the challenge-equals-verifier degenerate case
- **Longer lived auth codes**: rejected, 60 seconds is enough for a redirect hop and code lifetime is pure attack surface
