# Threat Model

The threats the platform is built against, each paired with the mitigation that actually exists in code, with file references. The last section lists what is deliberately not mitigated, because a threat model that only contains wins is marketing.

## Summary

| Threat | Primary mitigation | Where |
|---|---|---|
| Password brute force and spraying | Two layer login limits, argon2id at ~200 ms per attempt | `src/middleware/rateLimit.ts`, `src/services/password.ts` |
| Credential stuffing | Same limits, per client silos bound the blast radius | `src/middleware/rateLimit.ts`, `src/db/schema.ts` |
| Account enumeration | Uniform errors, uniform 200s, dummy hash timing | `src/routes/auth.ts`, `src/routes/account.ts` |
| Refresh token theft and replay | Rotation, single use, family revocation, client binding | `src/routes/auth.ts` |
| Access token theft | 15 minute lifetime, that window is the accepted contract | `src/services/token.ts` |
| Token forgery | EdDSA signatures, algorithm pinned per key type, issuer required | `src/services/token.ts` |
| Phishing through platform emails | Link URLs are registered configuration, never request input | `src/routes/account.ts`, ADR 0005 |
| OAuth code interception | 60 second single use codes, PKCE S256, registered redirect URIs | `src/services/oauth.ts`, `src/routes/oauth.ts` |
| OAuth state tampering and replay | AES-256-GCM with nonce, 10 minute expiry | `src/services/oauth.ts` |
| OAuth account squatting | Only verified provider emails, linking mismatches refused | `src/services/oauth.ts`, `src/routes/oauth.ts` |
| Cross tenant escalation | Ownership asserted on every role and permission mutation | `src/routes/roles.ts`, `src/routes/users.ts` |
| Database disclosure | Every credential hashed at rest | throughout |
| Request flooding | 16 KB body cap, limiters, nginx outer layer | `src/app.ts`, `nginx/auth.conf` |

## Guessing attacks

**Brute force against one account.** 5 login attempts per minute per account per IP, and each attempt costs the server (and so the attacker's wall clock) roughly 200 ms of argon2id at 64 MB memory, 3 iterations, 2 lanes. Passwords are 8 to 128 characters.

**Spraying across accounts.** The second limiter layer caps any single IP at 30 login attempts per minute regardless of how many emails it rotates through. The two layers exist so that shared institutional IPs stay usable, the reasoning is in [operations/rate-limiting.md](operations/rate-limiting.md).

**Stuffing leaked credential lists.** Same throttles apply. Per client silos add a structural bound: a credential valid for one application proves nothing about another, the same email under two clients is two unrelated accounts with independent passwords. There is no cross application pivot to make.

**Guessing tokens instead of passwords.** Refresh tokens are 48 random bytes, account tokens and OAuth codes 32, API keys 32. At 256 bits of entropy, online guessing is not a budgetable attack.

## Enumeration

Knowing which emails have accounts is the reconnaissance step for everything above, so the platform refuses to say:

- Login returns the same `INVALID_CREDENTIALS` for unknown email, wrong password and deactivated account, and hashes a dummy password when the user does not exist so response timing matches (`src/routes/auth.ts`)
- Forgot password and send verification answer 200 with the same message whether or not the account exists
- Consuming a reset or verification token returns one identical error for unknown, expired, used, wrong purpose and wrong client (`src/routes/account.ts`)

Registration necessarily reveals existence through `EMAIL_EXISTS`, that is inherent to registration. It sits behind the 5 per minute strict limiter, and invite only tenants close it entirely.

## Stolen tokens

**Refresh token theft is detectable by design.** Rotation makes every refresh token single use, so a thief and the legitimate user end up presenting the same token and whoever is second trips family revocation: all of the user's sessions die together ([ADR 0002](adr/0002-opaque-rotating-refresh-tokens.md)). Confidential clients add client credential binding, possession of the token alone is insufficient.

**Access token theft is time boxed, not detectable.** A stolen access token works until expiry, at most 15 minutes by default, and nothing can recall it because verification is offline. This is the platform's one deliberately accepted window, stated as contract in [contracts/sessions-and-tokens.md](contracts/sessions-and-tokens.md). Deployments needing a tighter bound shrink `JWT_ACCESS_EXPIRY` or re-verify remotely for sensitive operations.

**Forging tokens instead of stealing them.** Tokens are Ed25519 signed and the verifier pins the algorithm to the key type: an HS256 header can only ever meet the legacy secret, an EdDSA header only the public key, so a token cannot choose the weaker path (`src/services/token.ts`). The issuer claim is required on every verification.

## The email channel

**Phishing through the platform's own mails.** Once real: request supplied link URLs plus public client ids let anyone send authentic platform email whose reset link pointed at an attacker domain. Closed by making link targets registered configuration ([ADR 0005](adr/0005-registered-email-link-urls.md)). The remaining surface, triggering a legitimate mail to a victim, sends links only where the operator registered.

**Stolen reset links.** Tokens in links are single use, purpose bound, client bound and short lived (1 hour reset, 24 hour invites and verification), and only their SHA-256 lands in the database. A completed reset also revokes every session, so a reset link cannot quietly coexist with a hijacked session.

## The OAuth flows

- **Code interception.** Authorization codes live 60 seconds in Redis as hashes and are consumed by an atomic get and delete, one redemption ever. Public clients additionally bind codes to a PKCE S256 challenge, redeemable only with the matching verifier, compared in constant time
- **Redirect manipulation.** `redirect_uri` must be registered on the client, checked at initiation and again bound into the code at exchange. No registered URIs, no OAuth
- **State tampering and replay.** State is AES-256-GCM encrypted (tamper evident by authentication tag), carries a nonce and expires after 10 minutes
- **Account squatting via provider.** GitHub profile emails are attacker settable, so only verified provider emails are accepted, an account with none is refused. An email already linked to a different provider identity answers `OAUTH_ACCOUNT_MISMATCH` instead of silently merging

## Inside the platform

**Cross tenant escalation.** Every mutation that touches roles or permissions asserts the objects belong to the caller's client (`assertPermissionsBelongToClient`, ownership checks on assign, revoke, update and provisioning). Uniqueness constraints are per client. A refresh token presented through the wrong client's credentials fails before rotation.

**Database disclosure.** A read of the database yields argon2id hashes for passwords and SHA-256 hashes for refresh tokens, account tokens, client secrets and API keys. The unsalted SHA-256 is a considered choice for those four: they are 256 bit random values, not human chosen secrets, so rainbow style precomputation has nothing to grab. Passwords, the human chosen case, get the memory hard treatment.

**Malicious payloads.** All input crosses zod schemas with length bounds, bodies are capped at 16 KB and helmet sets the header baseline.

## Accepted and unmitigated, on purpose

Stated here so nobody discovers them as surprises:

- **No MFA yet.** A correct password is sufficient. TOTP is Phase 3 on the roadmap, demand driven. Until then the compensations are the throttles and hashing above
- **The 15 minute revocation window.** Described throughout, it is the price of offline verification and it is paid knowingly
- **Rate limiting fails open in a Redis outage** ([ADR 0004](adr/0004-fail-open-rate-limiting.md)). During that window only argon2id cost and the nginx layer throttle guessing
- **The admin key is one shared secret** with no audit trail. Honest for a single operator deployment, superseded when delegated administration lands
- **No login anomaly detection.** Refresh metadata (IP, user agent) is recorded, family revocation catches concurrent token use and users can inspect and revoke their own sessions through the sessions API, but there is no impossible travel or new device heuristic on the platform side

Found something this model misses? See [SECURITY.md](../SECURITY.md) for how to report it.
