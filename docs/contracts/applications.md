# Contract: Applications

How an application becomes a consumer of the platform: registration, client types, secrets, configuration and what deactivation means.

## Who invokes

Only the operator, with the admin key (`X-Admin-Key`, compared in constant time). No user token, API key or client credential can create, modify or list clients. The management APIs inside a client's silo are the client's own business, the existence and configuration of clients is the operator's.

## What is guaranteed at registration

`POST /clients` returns the client's identity exactly once:

- `clientId` (`cl_` plus 16 random bytes), permanent and treated as public knowledge
- `clientSecret` (`cs_` plus 32 random bytes) for confidential clients only, shown once, stored only as a SHA-256 hash and unrecoverable afterwards. Lose it and the answer is rotation, not retrieval

A client registered with `isPublic: true` gets no secret, ever. The public client containment story (PKCE, registered redirect URIs, rotation) is defined in [ADR 0006](../adr/0006-public-clients-with-pkce.md).

## Configuration is contract

Four settings on the client record change what the platform will and will not do, and all are settable only through this admin surface:

| Setting | Effect |
|---|---|
| `allowUserRegistration` | `false` closes `POST /auth/register` for this client (`REGISTRATION_DISABLED`). Users then exist only through provisioning or bootstrap |
| `redirectUris` | The complete list of OAuth landing points. Empty list means no OAuth at all |
| `passwordResetUrl` | Where reset and invite links point. Unset means those flows refuse with `RESET_URL_NOT_CONFIGURED` |
| `emailVerifyUrl` | Same rule for verification links |

Request input never overrides any of these. That rule exists because it was once violated and exploited (see [ADR 0005](../adr/0005-registered-email-link-urls.md)).

## Secret rotation and deactivation

- `POST /clients/:id/rotate-secret` issues a new secret and invalidates the old one in the same operation. There is no overlap window: the application redeploys with the new secret or its auth calls fail as `INVALID_CLIENT` until it does. Rotate at a deploy boundary
- `PATCH /clients/:id` with `isActive: false` shuts the whole silo immediately. Every credentialed call (login, refresh, register, the mail flows, OAuth) answers `INVALID_CLIENT`. Users and data remain intact and reactivation is the same PATCH with `true`
- API keys and service account keys of a deactivated client stop authenticating immediately, on both the direct `ApiKey` path and remote `/auth/verify`. They are checked against the database per request, so deactivation reaches them at once with no window
- Already issued access tokens are the one exception, not recalled by deactivation because they verify offline. They ride out their at most 15 minute lifetime, the same revocation window as everywhere else ([sessions-and-tokens.md](sessions-and-tokens.md))

## Tenant bootstrap

`POST /clients/:id/bootstrap` turns a freshly registered client into an administrable tenant in one call: it creates the eight management permissions, an admin role holding them and an invited first admin whose emailed link (valid 24 hours) sets their password.

Guaranteed properties:

- Refuses until `passwordResetUrl` is configured, the invite has to land somewhere registered
- Tolerant of reruns: existing permissions and an existing role of the same name are reused, not duplicated. Only the admin email must be new (`EMAIL_EXISTS` otherwise)
- Tolerant of mail outages: if the invite email fails, the response is still 201 with a warning and the tenant is fully usable. The admin gets their link through the password reset flow once mail is back
- The invited admin has no password until the link is used, and an unused invite expires harmlessly

## What consumers may assume

- The `clientId` string is stable for the client's lifetime, safe to bake into deployed configuration and safe to expose in frontend bundles
- The external `clientId` is also the access-token `aud` value. Consumers must verify it before accepting a token
- The internal client UUID remains available as `cid` for identity-silo context. It is not the token audience, see [sessions-and-tokens.md](sessions-and-tokens.md)
- Nothing about another client is observable from inside a silo. Users, roles, keys and configuration are invisible across clients in both directions

## When this can change

The show once rule for secrets, the registered configuration rule and silo isolation are stable API. The admin key mechanism is explicitly the simplest honest thing for a single operator deployment and will be superseded by delegated administration (Phase 3), additively, with the header based path deprecated on an announced schedule rather than removed.
