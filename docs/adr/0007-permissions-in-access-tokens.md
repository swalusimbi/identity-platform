# ADR 0007: Permissions baked into access tokens with bounded staleness

Status: accepted

## Context

Consumers need to answer "may this user do X" on every protected request. The permission data lives in the platform's database (user roles joined to role permissions). Either consumers ask the platform per request, or the answer travels inside the token and goes stale the moment a role changes.

## Decision

Flatten the user's permissions into the access token at issuance. The `permissions` claim carries strings like `["users:read", "billing:*"]`, resolved by walking user roles to role permissions at login and refresh time (`src/services/session.ts`). Consumers authorize entirely from the claim: exact match, `resource:*` wildcard or the `*` superkey.

Staleness is bounded by the access token lifetime, 15 minutes by default. Granting or revoking a role takes effect on the user's next refresh, at most one token lifetime later. The same bound applies to deactivation: refresh tokens die immediately but an already issued access token rides out its TTL.

This is a contract, not a leak in one: consumers are told to treat the window as the revocation guarantee ([contracts/sessions-and-tokens.md](../contracts/sessions-and-tokens.md)) and to size `JWT_ACCESS_EXPIRY` to their tolerance.

## Consequences

- Zero authorization lookups per request in every consumer, which combined with ADR 0001 makes the normal request path fully platform free
- Permission changes are not instant. An operator who needs a user out now revokes their sessions (deactivation does this) and accepts the residual 15 minutes, or rotates the signing key to burn every outstanding token at once
- Token size grows with permission count. Flattened strings for a single client's catalog are small in practice, and per client silos (ADR 0003) keep catalogs from unbounded growth
- The `permissions` claim shape is public API. Consumers parse it, so renaming or restructuring it is a breaking contract change

## Alternatives considered

- **Per request permission lookup at the platform**: rejected, reintroduces the synchronous dependency that local verification just removed
- **Short lived permission cache in each consumer**: rejected, same staleness tradeoff as the claim but with per consumer cache invalidation bugs instead of one documented window
- **Sessions table consulted on verification**: rejected, that is remote verification wearing a different hat
