# ADR 0004: Rate limiting fails open when Redis is down

Status: accepted

## Context

Login rate limiting is backed by Redis fixed window counters. Redis will occasionally be unavailable: a restart, a deploy, a network blip. At that moment every login for every application flows through a limiter that cannot count. Someone has to choose whether that means "allow" or "deny", and the choice is a product decision, not an implementation detail.

## Decision

Fail open. When the Redis transaction errors, the limiter logs the failure and lets the request through (`src/middleware/rateLimit.ts`). A Redis outage degrades brute force protection instead of taking authentication down for every user of every application.

The supporting design accepts the tradeoff knowingly:

- Password hashing is argon2id at 64 MB memory, 3 iterations, 2 lanes, roughly 200 ms per attempt. Even unthrottled online guessing is slow and expensive
- The sample nginx config in `nginx/auth.conf` provides an outer rate limiting layer that does not share Redis's fate
- The window is an outage window, not a permanent stance. Redis recovering restores the limits with no intervention

Availability was weighed directly against abuse resistance: identity is the highest blast radius service in the organization, and "nobody can log in because a cache restarted" is a worse failure than "brute force runs unthrottled during an outage, against 200 ms hashes, behind nginx limits".

## Consequences

- Redis is not on the critical path for password login. It is on the critical path for OAuth sign in, because authorization codes live in Redis and that flow fails closed (documented in [operations/availability.md](../operations/availability.md))
- Monitoring matters: a fail open limiter hides its own outage from users, so the limiter logs every failure and `GET /health` reports Redis state and returns 503 when it is down
- The `X-RateLimit-*` headers disappear during the outage, which is the observable signal a client sees

## Alternatives considered

- **Fail closed**: rejected, turns a cache restart into an organization wide login outage. For an identity platform that inverts the actual risk profile
- **In memory fallback counters**: rejected, per process counters behind a proxy give a false sense of limiting while multiplying the real limit by the process count, and the failure mode becomes harder to reason about than an honest open window
