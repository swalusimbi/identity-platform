# Operations: Rate Limiting

Redis backed fixed window counters in front of the endpoints where guessing pays. The design goal is stated as a person: many legitimate users behind one shared IP must not be able to starve each other, while one attacker behind that same IP still gets stopped.

## The two layer login limiter

Institutions share IPs. An office, a hospital, a campus NAT can put hundreds of legitimate users behind one address, and a naive per IP limit turns one person's typo streak into everyone's lockout. Login therefore gets two layers (`src/middleware/rateLimit.ts`):

| Layer | Key | Limit |
|---|---|---|
| Per account | IP + client + lowercased email | 5 per minute |
| Per IP | IP alone | 30 per minute |

The per account layer is the strict one: five tries against one mailbox per minute, then that account (from that IP) waits, while colleagues keep logging in unaffected. The per IP layer is the coarse backstop against spraying many accounts from one address: whatever mix of emails an attacker rotates through, an IP gets 30 login attempts per minute in total.

Password spraying from a single IP is bounded to 30 accounts per minute at 5 tries each within the same window, on top of argon2id making each attempt cost about 200 ms of server side hashing.

## The strict limiter

Register and the mail requesting and consuming flows (`/auth/register`, `/auth/password/forgot`, `/auth/password/reset`, `/auth/email/send-verification`) share a flat 5 per minute per IP. These endpoints either create accounts or send email, both of which are abusable at volume and neither of which a legitimate user does often.

## What is deliberately not limited in the app

`/auth/refresh`, `/auth/logout`, `/auth/verify` and the JWKS endpoint carry no application level limiter. Refresh and logout are gated by possession of a valid refresh token plus client credentials, verify and JWKS are consumer hot paths where added latency multiplies across every application. The outer nginx layer (`nginx/auth.conf`) still applies to them, which is the right place for plain volume control.

## Mechanics

Fixed window counters in Redis. Each request runs INCR, EXPIRE and TTL in a single MULTI so a crash between increment and expiry can never leave a counter without a TTL, the classic stuck key failure of naive implementations. The expiry uses NX so only the first request of a window sets it.

Every limited response carries the standard headers:

```
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 2
X-RateLimit-Reset: 1719990000
```

and an exceeded limit answers 429 with the seconds until the window resets. Clients should honor `X-RateLimit-Reset` rather than hammering.

## Failure behavior

Redis down means the limiter fails open and logs each failure, the full reasoning lives in [ADR 0004](../adr/0004-fail-open-rate-limiting.md). Operationally that means two things: alert on the limiter's error logs (users see nothing) and remember that `GET /health` reporting `redis: down` also means this protection is offline.

## Tuning

The numbers (5, 30, one minute windows) are operational tuning, not contract. Raise the per IP layer if a genuinely large institution sits behind one address, the per account layer is the one doing the security work and should stay strict. The two layer structure itself is the stable part of the design.
