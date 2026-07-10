# ADR 0010: Operation-bound refresh retries

Status: accepted

## Context

ADR 0002 treats every replay of a rotated refresh token as theft and revokes every session the user has. That inference is too strong when a client sends a valid refresh request, the platform commits the rotation and the response is lost. Retrying the old token after that transport failure is normal recovery, but the platform cannot distinguish it from theft without another proof.

The platform stores refresh tokens only as SHA-256 hashes. It cannot return the exact successor again because the raw token cannot be recovered from its hash. Storing a recoverable token response would weaken the database breach boundary established by ADR 0002.

## Decision

Every refresh request carries a client-generated `operationId`. It must be a fresh random UUID for a new refresh operation and it must be reused only when retrying an ambiguous result from that operation. The platform stores only its SHA-256 hash on the consumed refresh-token row.

The first redemption remains single use and atomic:

- Revoke the predecessor only when it is active and unexpired
- Record the operation hash, rotation time and successor id on the predecessor
- Insert the successor in the same database transaction

A request presenting a rotated token is accepted as a retry only when all of these are true:

- Its operation hash matches the hash recorded by the first redemption
- It arrives within `REFRESH_RETRY_GRACE_SECONDS`, 10 seconds by default
- The recorded successor still exists, is active and is unexpired

An accepted retry atomically revokes the unused successor with reason `retry`, issues a replacement pair and updates the predecessor to point at the replacement. The original rotation time does not move, so repeated retries cannot extend the grace period.

A mismatched operation id, an expired grace period or an already-used successor follows the ADR 0002 security path and revokes every active refresh token for the user. Tokens revoked by an accepted retry answer a plain 401 if they arrive later because their invalidation was caused by response recovery, not proof of theft.

Consumers must still serialize refresh work per stored session. They must replace stored tokens atomically and ignore stale responses. The grace path handles a lost response, not normal browser-tab or multi-instance coordination.

## Consequences

- A transient response loss no longer signs the user out everywhere when the consumer retries correctly
- A stolen predecessor is not enough to enter the grace path because the attacker must also know the operation id used by the legitimate refresh
- Refresh requests without a valid operation id are rejected before token consumption
- A database leak still yields no usable refresh token or operation id
- Existing rotated rows have no operation hash or successor pointer, so replay of those rows keeps the strict ADR 0002 behavior
- The refresh API and SDK contract gain a required operation id

## Alternatives considered

- **Return the original response on retry:** rejected because it requires storing raw successor material in recoverable form
- **Use only a time-based grace window:** rejected because a thief holding the predecessor could revoke the legitimate successor and obtain a replacement during the window
- **Keep strict replay revocation:** rejected because a lost response is a normal transport failure and does not prove two independent holders
- **Allow unlimited retry replacement:** rejected because it removes the bounded theft signal and lets possession of old retry material disrupt a session indefinitely
