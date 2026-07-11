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

## Mail fails fast and fails contained

`sendMail` is awaited on the request path, but the transport carries bounded timeouts (10 seconds each for connection and greeting, 15 for the socket) so a hanging SMTP server surfaces as a fast, attributable 502 `MAIL_UNAVAILABLE` from the platform instead of an anonymous 504 from the reverse proxy. The production incident behind this left two findings worth keeping:

- Many hosting providers block outbound ports 25 and 465 by default. Use a submission service on port 587 and make sure the `SMTP_URL` scheme matches the port (`smtp://` with STARTTLS on 587, `smtps://` on 465)
- Alert on the 502 rate of the mail sending routes. Before the timeouts existed the failure surfaced as proxy latency, now it is an explicit error code

How each flow behaves during a mail outage:

| Flow | Behavior |
|---|---|
| Forgot password, send verification | 502 `MAIL_UNAVAILABLE`, the mail is the whole point, retrying is correct |
| Tenant bootstrap | 201 with a warning. The tenant is fully created, the admin requests their link through the password reset flow once mail is back |
| User provisioning | 201 with `invited: false` and a warning, same retry path |

## Built in self maintenance

- A daily cleanup job prunes refresh and account tokens 30 days after expiry, keeping replay detection intact while stopping unbounded table growth. It runs at startup and every 24 hours, on an unref'd timer that never blocks shutdown
- Request bodies are capped at 16 KB, helmet sets the security headers and `trust proxy` is 1, matching the single reverse proxy deployment shape in `nginx/auth.conf`

## Production checklist

- TLS terminates at a reverse proxy, the sample nginx config includes its own rate limiting layer that does not share Redis's fate
- `CORS_ORIGINS` is set if browsers call the platform directly, unset means browser requests are refused in production. Server to server integrations need nothing
- Ed25519 keys are configured. Production startup fails without them by design, the HS256 fallback and its disabled JWKS exist for development only
- `GET /health` is monitored per dependency, a `redis: down` platform is degraded (no OAuth, no rate limits) long before it is down
