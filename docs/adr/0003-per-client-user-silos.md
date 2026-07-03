# ADR 0003: Per client user silos now, user pools as the designed extension point

Status: accepted

This is a decision not to build something, recorded so the boundary it draws stays deliberate.

## Context

Every application registers as a client and gets its own users, roles, permissions and API keys. The same email under two clients is two unrelated accounts (`users_client_email_idx` is unique on client id plus email). The client entity is doing two jobs at once: it is the application and it is the identity boundary, and the `cid` token claim carries both meanings.

The obvious platform move is shared identity, one account usable across applications. The mission ("any application inside an organization") eventually demands it, and every consumer who runs two apps will eventually ask for it.

## Decision

Keep users strictly per client for now. Do not introduce shared identity as a patch, a per client flag or a special "shared" client.

The designed extension is the **user pool** (Phase 3 on the roadmap): the pool becomes the identity boundary and an application attaches to exactly one pool. Many apps on one pool is shared identity with SSO. One app per pool is today's model and remains the default. Neither topology is "the model", the pool is the model and topology is configuration.

Migration is defined in advance: every existing client becomes a pool containing one application, semantics preserved exactly. The acceptance test for the whole phase is that an existing consumer redeploys against the new platform with zero configuration changes and notices nothing, including in what its isolation guarantees mean.

## Consequences

- Full isolation today. No accidental account linking, no cross app data questions, each application fully self contained
- The `cid` claim will eventually split into two claims, who the user is (pool) and which app the token is for (client). Consumers that pin `cid` semantics will need the new claim contract, which is why phase 3 ships it as opt in topology rather than a new default
- The unfusing bill is known and unpaid: real SSO means a platform level session minting per app tokens, email links need an answer for which app's branding a shared user sees and lifecycle blast radius grows (deactivation spans a pool, email uniqueness scope changes)

## Alternatives considered

- **Global users from day one**: rejected, forces SSO semantics, cross app privacy answers and federated lifecycle onto single app consumers who wanted none of it
- **A shared flag on clients**: rejected, it hard codes one topology into a boolean and leaves the client entity still doing two jobs. The pool names the second job properly
