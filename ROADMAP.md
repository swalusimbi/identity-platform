# Roadmap

The platform grows in capability layers. Each layer depends on the one below it and none replace it: a consumer integrated against an earlier layer keeps working, with the same guarantees, as later layers ship. The guiding test for every addition:

> Would another engineering team reasonably expect an identity platform to provide this?

## Phase 1 - Identity Foundation

The platform establishes and manages identities: authentication, authorization, token issuance and the account lifecycle.

- [x] Registration, login, logout
- [x] Argon2id password hashing with timing attack protection
- [x] EdDSA signed access tokens, verifiable offline through JWKS
- [x] Opaque refresh tokens with rotation and family revocation on replay
- [x] Password reset, email verification and password change with single use emailed tokens
- [x] Role based access control with per client permission catalogs and wildcards
- [x] Audit logging (who did what, when, from where). Foundation tier because history cannot be recreated after the fact
- [x] Sessions API: list a user's active sessions, revoke one or all

## Phase 2 - Platform Foundation

The platform becomes a shared service for any number of applications.

- [x] Applications as first class clients, confidential and public (PKCE), secret rotation, deactivation
- [x] Per client user silos: each application is a fully isolated tenant
- [x] API keys with scopes for machine to machine access
- [x] Invite-only tenants: registration toggle, user provisioning API with emailed invites, one call tenant bootstrap
- [x] Two layer login rate limiting fair to many users behind one NAT
- [x] Pluggable mail delivery (SMTP, console)
- [x] Drop in TypeScript SDK
- [ ] Service accounts as a named concept, richer than scoped API keys
- [x] OpenAPI specification
- [ ] Admin console over the existing management APIs

## Phase 3 - Enterprise Identity

The platform integrates into existing enterprise ecosystems. The foundational move comes first and everything else attaches to it.

- [ ] **User pools**: separate the identity boundary from the application. Today they are fused, every client is its own silo. Pools make the topology configurable: many applications sharing one user pool (an organization's internal suite, with SSO) or one application per pool (today's model, which remains the default). Existing clients migrate as single application pools and notice nothing
- [ ] Federation: bring your own identity provider (the enterprise already has a directory)
- [ ] Single sign on across applications that share a pool
- [ ] SCIM provisioning as a protocol adapter over the user management API
- [ ] Delegated administration (platform admin, organization admin, department admin)
- [ ] Multi factor authentication (TOTP first)
- [ ] Compliance grade audit queries

### The deliberate model change

Phases 1 and 2 grew purely additively. The first Phase 3 item is different: it changes what the identity boundary is, which is why it ships as opt in topology rather than a new default. The acceptance test for every Phase 3 change is that an existing consumer can redeploy against the new platform with zero configuration changes and notice nothing, including in what its isolation guarantees mean.
