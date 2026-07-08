# ADR 0009: Service accounts are role-bearing machine principals

Status: accepted

Service accounts are the first principal type added after users and scoped API keys.

## Context

API keys already have names, scopes and metadata. Renaming that shape to "service account" would not add a capability. The missing capability is separation of credential from grant: rotate the credential without changing permissions and change permissions without reissuing the credential.

The platform currently has one authorization rule everywhere: does the principal's permission set satisfy `resource:action`. Adding key scopes that intersect with role permissions would be more expressive, but it would add a second rule that every consumer and management endpoint would need to explain.

ADR 0008 named a third principal type as the trigger to revisit a generic Principal table.

## Decision

Add service accounts as named, per-client machine principals with role assignments:

- `service_accounts` stores the account identity, name, description and active flag
- `service_account_roles` assigns roles to service accounts, parallel to `user_roles`
- `api_keys.service_account_id` optionally attaches a key to a service account
- A service account key stores no scopes. It authenticates as the service account
- Service account permissions are resolved live from roles on each API key authentication and `/auth/verify` call
- Plain scoped API keys remain unchanged

Do not introduce a generic Principal table yet. The revisit trigger fired, but the conclusion is still "not now". The current duplication is two join tables with identical shape. A polymorphic assignment table would require a production migration and changes to token issuance, seed paths and bootstrap for no immediate capability.

## Consequences

- Service account offboarding is one update: set `is_active = false` and every attached key stops authenticating
- Permission changes for service accounts are immediate because keys are checked against the database per request
- Users keep the existing token staleness model from ADR 0007
- Workloads that need two different permission sets should use two service accounts
- A future optional key narrowing model remains additive because service account keys currently have an empty scope list

## Alternatives considered

- **Rename API keys as service accounts**: rejected. It adds terminology without the credential and grant separation that users expect from service accounts
- **Service account roles intersected with key scopes**: rejected for now. It is a valid enterprise model, but it adds a second authorization algebra before the product needs it
- **Generic Principal and RoleAssignment tables now**: rejected. The migration is not worth it until another feature needs uniform principal handling
