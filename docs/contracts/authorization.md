# Contract: Authorization

Answering what an authenticated principal may do. The vocabulary is permission strings, the structure behind them is roles for users and scopes for API keys.

## The vocabulary

A permission is `resource:action`, for example `users:read` or `billing:write`. Three forms satisfy a check for `users:delete`:

| Granted | Why it matches |
|---|---|
| `users:delete` | Exact |
| `users:*` | Resource wildcard |
| `*` | Superkey, matches everything |

The same strings and the same matching rules apply to user permissions and API key scopes. A route protected by `users:write` does not care which kind of principal presents it (`src/middleware/authorize.ts`).

## Who invokes and what they prove

Permission checks happen in two places with identical semantics:

- **Inside consumers**, against the `permissions` claim of a locally verified access token. No platform involvement
- **At the platform**, on the management APIs (`/users`, `/roles`, `/api-keys`) and optionally through `POST /auth/verify` with a `requiredPermission`, where the response distinguishes `valid` (genuine artifact) from `authorized` (also holds the permission)

Managing the authorization data itself requires, per capability: `roles:read` or `roles:write` for the role and permission catalog, `users:write` for provisioning and role material at invite time, `api-keys:read` or `api-keys:write` for keys.

## What is guaranteed

- **Everything is per client.** Roles, the permission catalog and assignments live inside one client's silo. Role names are unique per client, permission `resource:action` pairs are unique per client and the platform refuses to attach another client's permissions or roles (`UNKNOWN_PERMISSION`, `UNKNOWN_ROLE`, checked against ownership on every mutation)
- **Permissions reach consumers only through tokens.** The user's roles are flattened into the `permissions` claim at login and refresh. There is no side channel that could disagree with the token
- **Default roles are automatic.** Roles marked `isDefault` are assigned at registration and at first OAuth sign in, so a fresh user's first token already carries the intended baseline
- **The management bootstrap is fixed.** Tenant bootstrap creates exactly six permissions (`users`, `roles` and `api-keys`, each `read` and `write`) and binds them to the admin role it creates. A tenant's first admin can manage users, roles and keys and nothing else until someone grants more

## What consumers may assume

- **Staleness is bounded by the access token lifetime.** A role granted or revoked takes effect on the user's next refresh, at most 15 minutes (default) after the change. This is the same revocation window defined in [sessions-and-tokens.md](sessions-and-tokens.md), authorization inherits it rather than adding its own
- API key scope changes do not exist, keys are immutable except for revocation. To change a machine's access, issue a new key and revoke the old one. Revocation is immediate because keys are checked per request
- `requireAnyPermission` style OR checks exist on the platform side. Consumers implementing their own checks against the claim should replicate the three matching forms above and nothing subtler, there is no hierarchy, no implication and no deny rule

## The boundary with domain authorization

The platform owns identity and each application's management permissions. It deliberately does not own domain authorization: org memberships, project access, "which hospital does this doctor belong to". Consuming applications model those themselves, using `sub` as the join key. The litmus test: if another engineering team would not expect an identity platform to know it, the platform does not want it.

## When this can change

The string vocabulary, the three matching forms and the per client isolation are stable API, the `permissions` claim shape is load bearing for every consumer. Service accounts (roadmap) will arrive as a new principal carrying the same vocabulary. If a richer model ever supersedes flat strings it will be additive, tokens will not stop carrying `permissions`.
