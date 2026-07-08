# Contracts

A platform is defined by what consumers may rely on, not by its feature list. Each contract here answers the same five questions: who may invoke the capability, what they must prove, what the platform guarantees, what consumers may assume and when any of it can change.

Wire level details live in the [OpenAPI specification](../openapi.json), with a human guide in the [API reference](../AUTH-API-DOCS.md). These documents cover the meanings, which are the part that stays stable.

| Contract | Covers |
|---|---|
| [authentication.md](authentication.md) | Register, login, refresh, logout and the OAuth flows |
| [sessions-and-tokens.md](sessions-and-tokens.md) | Token formats, claims, lifetimes, rotation and the revocation window |
| [authorization.md](authorization.md) | Permissions, roles, wildcards, API key scopes and staleness |
| [service-accounts.md](service-accounts.md) | Role-bearing machine principals and their credentials |
| [applications.md](applications.md) | Client registration, types, secrets, deactivation and tenant bootstrap |
| [account-lifecycle.md](account-lifecycle.md) | Invites, password reset, email verification, password change, deactivation |
| [audit.md](audit.md) | The audit record, event catalog, read access and retention |

A breaking change to any guarantee below is announced in the changelog of the release that ships it, with a migration path. Additive changes (new endpoints, new optional fields, new error codes for new situations) can arrive in any release.
