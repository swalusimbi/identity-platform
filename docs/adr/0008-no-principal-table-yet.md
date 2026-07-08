# ADR 0008: No Principal table until a third principal type exists

Status: accepted

Superseded in part by [ADR 0009](0009-service-accounts-with-roles.md), which revisits the trigger and keeps the Principal table deferred.

A second decision not to build, with its trigger written down.

## Context

The platform has two kinds of authenticated principal: users, who get permissions through roles, and API keys, which carry flat scopes directly. Textbook modeling says unify them: a `Principal` entity with `RoleAssignment` rows, so users, keys and whatever comes next share one authorization structure.

## Decision

Do not introduce the Principal abstraction now. With exactly two principal types, the unification would be structure without a customer: a join table, a polymorphic foreign key and migration work, purchased before anything needs to vary across it.

The unification that actually matters already exists at the vocabulary level. Users' role derived permissions and API key scopes are the same `resource:action` strings, checked by the same logic with the same wildcard rules (`src/middleware/authorize.ts`, `src/services/apiKey.ts`). A route guarded by `requirePermission("users:write")` accepts either principal and cannot tell them apart, which is the property a Principal table would exist to provide.

**The trigger to revisit:** a third principal type. Service accounts as a named concept richer than scoped API keys are the likely candidate (Phase 2 refinement on the roadmap). When they arrive, generalizing two working principal types into three is a refactor with tests behind it. Generalizing one imagined type ahead of time is speculation.

## Consequences

- Roles cannot be assigned to API keys. A machine needing broad access gets wildcard scopes (`users:*`), which has been sufficient for every consumer so far
- The permission string vocabulary is the extension point and its stability matters more than internal table shape. It is public API through the `permissions` claim (ADR 0007)
- When the Principal refactor comes it touches schema, token issuance and both middleware paths. The deferral is a real debt with a named repayment date, not a hope that the need disappears

## Alternatives considered

- **Principal and RoleAssignment tables now**: rejected as gold plating. Two types that already share their check logic gain nothing from sharing a table
- **Roles for API keys as a halfway step**: rejected, it duplicates the role machinery for keys without answering what a third principal needs, which is the only question that matters
