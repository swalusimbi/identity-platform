# Operations: Availability

When identity is down everything is down, so every dependency failure has a decided behavior rather than an accidental one. This document states each decision and what an operator sees.

## The health contract

`GET /health` checks Redis and Postgres and answers per dependency:

```json
{ "status": "ok", "redis": "ok", "database": "down" }
```

200 when everything is ok, 503 when anything is down. Point load balancer checks and uptime monitors here. The per dependency fields exist because the two failures degrade the platform very differently, as the table below shows.

## What fails open, what fails closed

| Dependency down | Password login | OAuth sign in | Refresh | Local JWT verification in consumers | Rate limiting |
|---|---|---|---|---|---|
| Redis | Works | **Down** | Works | Works | Open, unlimited |
| Postgres | **Down** | **Down** | **Down** | Works | Enforced |
| The platform process | **Down** | **Down** | **Down** | Works | n/a |
| SMTP | Works | Works | Works | Works | Enforced |

Two decisions worth spelling out:

- **Rate limiting fails open** ([ADR 0004](../adr/0004-fail-open-rate-limiting.md)). A Redis outage degrades brute force protection instead of blocking every login. The limiter logs each failure, watch for those logs because users will not report this state
- **OAuth fails closed on Redis** because authorization codes live there with a 60 second TTL and single use semantics that only Redis provides. Password login does not share this dependency, which is deliberate: the flow of last resort has the fewest dependencies

The last column of the first row is the design's payoff: consumers verify tokens locally, so a platform outage does not take down already signed in users of any application. Sessions survive for the access token lifetime (15 minutes by default) and the outage becomes visible only as failed refreshes after that. A platform recovery inside that window is invisible to most users.

## Mail is synchronous, plan for it

`sendMail` is awaited on the request path. If SMTP hangs, the requesting call (forgot password, invite, bootstrap) hangs with it until something times out, and behind a reverse proxy that something is typically the proxy, answering 504 to the user. This has happened in production; two findings from that incident are worth keeping:

- Many hosting providers block outbound ports 25 and 465 by default. Use a submission service on port 587 and make sure the `SMTP_URL` scheme matches the port (`smtp://` with STARTTLS on 587, `smtps://` on 465)
- The failure surfaces as a slow 5xx on the auth endpoint, not as a mail error, so alert on latency for the mail sending routes, not just on status codes

Connection and greeting timeouts on the mailer plus a bootstrap that tolerates mail failure are on the backlog. Until then, treat SMTP as a hard dependency of the mail flows and test it after any infrastructure change.

## Built in self maintenance

- A daily cleanup job prunes refresh and account tokens 30 days after expiry, keeping replay detection intact while stopping unbounded table growth. It runs at startup and every 24 hours, on an unref'd timer that never blocks shutdown
- Request bodies are capped at 16 KB, helmet sets the security headers and `trust proxy` is 1, matching the single reverse proxy deployment shape in `nginx/auth.conf`

## Production checklist

- TLS terminates at a reverse proxy, the sample nginx config includes its own rate limiting layer that does not share Redis's fate
- `CORS_ORIGINS` is set if browsers call the platform directly, unset means browser requests are refused in production. Server to server integrations need nothing
- Ed25519 keys are configured, the HS256 fallback and its disabled JWKS are for trying things out only
- `GET /health` is monitored per dependency, a `redis: down` platform is degraded (no OAuth, no rate limits) long before it is down
