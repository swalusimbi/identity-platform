# Contract: Audit

Who did what, when, from where. Audit sits in the foundation tier because history cannot be recreated after the fact: every other capability can be added later, a missing month of history cannot.

This contract was written before the implementation and the implementation follows it.

## The record

Every audited event is one append only row:

| Field | Contents |
|---|---|
| `id` | UUID |
| `clientId` | The silo the event belongs to, always set |
| `action` | Dotted event name from the catalog below, for example `user.login` |
| `actorType` | `user`, `api_key`, `operator` or `anonymous` |
| `actorId` | User id or API key id, null for operator and anonymous |
| `targetType` | What was acted on: `user`, `role`, `permission`, `api_key`, `client`, null when the actor is the target |
| `targetId` | Id of the target, null with it |
| `ip` | Requesting IP as the platform saw it |
| `userAgent` | Requesting user agent, may be null |
| `details` | Small JSON object with event specific facts (provider, role name, email for anonymous events). Never contains secrets, tokens or password material |
| `createdAt` | Server time of the event |

Rows are never updated or deleted inside the retention window. There is no update path in the code.

## Event catalog

**Authentication**

| Action | Actor | Notes |
|---|---|---|
| `user.registered` | the new user | Self service registration, `details.method` is `password` or the OAuth provider |
| `user.login` | user | `details.method` likewise |
| `user.login_failed` | anonymous | Wrong password or unknown email, `details.email` carries the attempted address |
| `user.logout` | user | |
| `session.replay_detected` | user | A revoked refresh token was presented, all sessions revoked. The security event of the token design |

Routine token refreshes are deliberately not audited: one row per user per access token lifetime is volume without signal, and the interesting case (replay) has its own event. Failed logins are bounded by the login rate limits, so `user.login_failed` cannot flood unboundedly.

**Account lifecycle**

| Action | Actor |
|---|---|
| `password.reset_requested` | anonymous, `details.email` |
| `password.reset_completed` | the user |
| `password.changed` | the user |
| `email.verified` | the user |
| `user.provisioned` | the inviting principal, target the new user |
| `user.deactivated` / `user.reactivated` | the acting principal, target the user |

**Authorization**

| Action | Actor |
|---|---|
| `role.created` / `role.deleted` | the acting principal, `details.name` |
| `role.permissions_replaced` | the acting principal, `details.permissionIds` |
| `role.assigned` / `role.revoked` | the acting principal, target the affected user, `details.roleId` |
| `permission.created` | the acting principal, `details` carries resource and action, bulk creation is one event per permission |

**API keys and clients**

| Action | Actor |
|---|---|
| `apikey.created` / `apikey.revoked` | the acting principal, target the key, never the key material |
| `client.created` / `client.updated` / `client.secret_rotated` / `client.bootstrapped` | operator, target the client |

Operator events carry the affected client's id as `clientId`, so every row in the table has a silo and client scoped reads see the operator actions that shaped their tenant.

## Who may read

`GET /audit`, authenticated, behind a dedicated `audit:read` permission. Deliberately not `users:read`: reading history is more sensitive than reading state and gets its own grant. Tenant bootstrap does not include it in the management role, an admin grants it knowingly.

Reads are scoped to the caller's client with no exceptions. Filters: `action`, `actorId`, `targetId`, `from`, `to`, plus `limit` (default 50, max 200) and `before` cursor for paging, newest first.

## What is guaranteed

- **Same transaction visibility.** The audit write happens in the request that caused the event, against the same database. A mutation you observed has its row queryable immediately after the response
- **Append only.** No API can modify or remove a row inside the retention window
- **No secrets.** Tokens, passwords, hashes, key material and client secrets never appear in `details`, only names, ids and coarse facts

## What is deliberately weaker

- **Audit failure does not fail the operation.** The write is awaited, but if it errors the user's action still succeeds and the failure is logged loudly for the operator. The alternative, refusing logins because the audit insert broke, was rejected for the same availability reasoning as fail open rate limiting ([ADR 0004](../adr/0004-fail-open-rate-limiting.md)). Since audit shares the platform's database, the realistic total failure case (database down) fails the operation anyway
- **Retention is bounded.** Rows older than `AUDIT_RETENTION_DAYS` (default 365) are pruned by the daily cleanup job. Deployments with compliance horizons set the variable higher or export before the cutoff

## When this can change

The row shape and the append only rule are stable API. The event catalog grows additively, consumers filtering by `action` should tolerate unknown actions appearing. Compliance grade queries (Phase 3) will extend the read API without changing the row.
