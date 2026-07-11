# Architecture Decision Records

Decisions that shaped the platform, recorded with the alternatives that lost and the consequences we accepted. Each record describes the system as it is in code, not as it might become.

| ADR | Decision |
|---|---|
| [0001](0001-eddsa-jwks-over-shared-secret.md) | EdDSA signatures with JWKS over a shared HMAC secret |
| [0002](0002-opaque-rotating-refresh-tokens.md) | Opaque rotating refresh tokens over JWT refresh tokens |
| [0003](0003-per-client-user-silos.md) | Per client user silos now, user pools as the designed extension point |
| [0004](0004-fail-open-rate-limiting.md) | Rate limiting fails open when Redis is down |
| [0005](0005-registered-email-link-urls.md) | Email links come from registered URLs, never from request input |
| [0006](0006-public-clients-with-pkce.md) | Public clients with PKCE over requiring a backend for frontend |
| [0007](0007-permissions-in-access-tokens.md) | Permissions baked into access tokens with bounded staleness |
| [0008](0008-no-principal-table-yet.md) | No Principal table until a third principal type exists |
| [0009](0009-service-accounts-with-roles.md) | Service accounts are role-bearing machine principals |
| [0010](0010-operation-bound-refresh-retries.md) | Operation-bound retries for ambiguous refresh results |
