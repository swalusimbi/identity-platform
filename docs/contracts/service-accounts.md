# Contract: Service accounts

Service accounts are named machine principals. They exist when a workload needs durable identity and role-based grants, not just one scoped credential.

## Who invokes and what they prove

Service account management APIs require an authenticated principal from the same client:

| Capability | Required permission |
|---|---|
| List service accounts | `service-accounts:read` |
| Create or update a service account | `service-accounts:write` |
| Assign or revoke service account roles | `service-accounts:write` |
| Create a key for a service account | `service-accounts:write` |

Every role assignment is checked against the caller's client. The platform refuses to attach another client's role to a service account.

## What is guaranteed

- A service account belongs to exactly one client
- A service account gets permissions through roles, using the same `resource:action` vocabulary and wildcard rules as users and API keys
- A service account key is only a credential. It stores no scopes and does not own the grant
- Service account permissions are resolved from the database on every API key authentication and every `/auth/verify` call
- Deactivating a service account immediately makes all of its keys unusable, even if the keys themselves are not revoked
- Plain scoped API keys remain supported. They are still the right fit for simple scripts that only need a fixed scope list

## What consumers may assume

Permission changes for service accounts are live. Assigning or revoking a role changes the result of the next request made with any key attached to that service account. There is no access-token staleness window because service account keys are checked against the platform on every request.

Consumers may distinguish a service account key from a plain API key by the optional `apiKey.serviceAccount` object returned by `POST /auth/verify`.

## What is deliberately not promised

Service account keys do not have additional narrowing scopes. If the same workload needs two different permission sets, create two service accounts. This keeps authorization to one rule: the principal's permission set must satisfy `resource:action`.

Service accounts do not introduce a generic Principal table yet. Users and service accounts currently use parallel role assignment tables because the shared behavior is small and the migration cost of a polymorphic assignment model is not justified.

## When this can change

Optional narrowing scopes may be added to service account keys later without breaking existing keys. A generic Principal or RoleAssignment model may replace the parallel tables if a future feature needs uniform principal handling across users, service accounts and another assignment consumer.
