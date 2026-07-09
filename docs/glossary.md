# Glossary

What words mean in this platform specifically. Where a term has a generic industry meaning, the entry states the platform's narrower one.

**Access token.** The short lived EdDSA signed JWT (15 minutes by default) that proves identity offline. Carries `sub`, `cid`, `email` and `permissions`. Never stored server side.

**Account token.** A single use, purpose bound token delivered in an email link: password reset (1 hour), email verification (24 hours) or invite (24 hours). Stored only as a SHA-256 hash.

**Admin key.** The shared secret (`ADMIN_KEY`, sent as `X-Admin-Key`) that identifies the operator. Guards the `/clients` surface and nothing else.

**API key.** An `sk_` prefixed machine credential carrying flat scopes. Checked against the database per request, so revocation is immediate. Shown once at creation.

**Audience.** Which application a token is intended for. Today the `cid` claim carries this together with the identity home, the two meanings split when user pools land.

**Claim.** A field inside the access token payload. The platform's claims are contract, consumers parse them ([contracts/sessions-and-tokens.md](contracts/sessions-and-tokens.md)).

**Client.** A registered application. Currently also the identity boundary: users, roles, permissions and API keys all belong to exactly one client. See silo and user pool.

**Client credentials.** The `cl_` client id plus, for confidential clients, the `cs_` secret. Presented by application backends on every authentication call.

**Confidential client.** A client whose backend can keep a secret and must present it. The default and stronger client type.

**Consumer.** An application that integrates with the platform: registers as a client, relays auth calls and verifies tokens locally.

**Credential.** Anything a principal presents as proof: a password, a token, a key, a secret. The [trust model](trust-model.md) enumerates all seven.

**Default role.** A role with `isDefault: true`, assigned automatically at registration and first OAuth sign in.

**Extension point.** A place where the design already reserved room for a future capability, so building it later is filling in rather than reworking. User pools are the flagship example.

**Fail open / fail closed.** What a capability does when its dependency is down: keep serving without the protection, or refuse. Each dependency has a decided answer in [operations/availability.md](operations/availability.md).

**Family revocation.** Revoking every refresh token a user has because one revoked token was presented again. Turns token theft into a detectable, self limiting event.

**Identity.** The platform's answer to "who is this", established once, proven by tokens and consumed by any number of applications.

**Issuer (`iss`).** The deployment's identity inside every token, defaulting to the service hostname. Verification requires it, tokens from another deployment fail.

**JWKS.** The JSON Web Key Set at `/.well-known/jwks.json` publishing the current public signing key. What lets consumers verify without holding any secret.

**kid.** The key id in the token header and JWKS, `identity-platform-v1` by default. Bumping it on rotation is how consumers learn a new key exists.

**Operator.** The person running the deployment: registers clients, rotates secrets, bootstraps tenants. Authenticated by the admin key.

**Permission.** A `resource:action` string like `users:read`. The single authorization vocabulary shared by user roles and API key scopes, wildcards `resource:*` and `*` included.

**PKCE.** Proof Key for Code Exchange (RFC 7636, S256 only here). How a public client, having no secret, proves the code redemption comes from the same party that started the flow.

**Principal.** Anything that can be authenticated: today users and API keys, unified at the vocabulary level rather than by a shared table ([ADR 0008](adr/0008-no-principal-table-yet.md)).

**Public client.** A client that cannot keep a secret (SPA, mobile app). Held by PKCE, registered redirect URIs and refresh rotation instead.

**Refresh token.** The opaque 48 byte, single use, 7 day credential that keeps a session alive and revocable. The revocable half of the session design.

**Revocation window.** The bounded time (at most one access token lifetime, 15 minutes by default) during which a revoked identity's outstanding access tokens still verify. The platform's central accepted tradeoff.

**Role.** A named bundle of permissions inside one client, assigned to users. Roles never cross clients.

**Scope.** A permission string attached directly to an API key rather than reached through a role. Same vocabulary, same matching.

**Session.** Concretely: one refresh token row with its IP and user agent metadata. Revoking the row is revoking the session, everything else follows from that.

**Silo.** One client's fully isolated world of users, roles, permissions and keys. The same email in two silos is two unrelated accounts.

**Subject (`sub`).** The user's UUID in every token, stable for the user's lifetime and the join key consumers use for their own domain data.

**Tenant.** A client viewed from the management side, especially an invite only one: registration closed, users provisioned, bootstrapped with an admin role.

**User pool.** The planned Phase 3 identity boundary, separating "where users live" from "which app is asking". Many apps on one pool is SSO, one app per pool is today's model and stays the default ([ADR 0003](adr/0003-per-client-user-silos.md)).
