# Contract: Authentication

Establishing who someone is: `POST /auth/register`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout` and the OAuth flows under `/auth/oauth`.

## Who invokes

Application backends, always with their client credentials. Confidential clients send `clientId` and `clientSecret` on every call. Public clients send `clientId` alone and are held by PKCE and rotation instead (see [applications.md](applications.md)).

End users never call these endpoints directly, their application does it for them. The exceptions are the two OAuth redirect hops (`GET /auth/oauth/:provider` and its callback), which the user's browser traverses.

## What they must prove

| Call | Proof |
|---|---|
| Register | Client credentials, an email of at most 320 chars, a password of 8 to 128 chars |
| Login | Client credentials plus the user's email and password |
| Refresh | Client credentials plus possession of a live refresh token belonging to that client's user |
| Logout | Same as refresh |
| OAuth initiate | A registered `redirect_uri`, plus a `code_challenge` (S256) if the client is public |
| OAuth token exchange | Client credentials, the 60 second code, the same `redirect_uri` and the PKCE verifier when the code was issued with a challenge |

## What is guaranteed

- **Credential failures are uniform.** Login answers `INVALID_CREDENTIALS` whether the email is unknown, the account is inactive or the password is wrong, and the platform hashes a dummy password when the user does not exist so the timing does not tell either
- **Client failures are uniform.** Unknown, inactive and wrong secret all answer `INVALID_CLIENT`
- **Registration respects the tenant's door policy.** A client created with `allowUserRegistration: false` answers `REGISTRATION_DISABLED` and its users exist only through provisioning (see [account-lifecycle.md](account-lifecycle.md))
- **A successful register, login or exchange returns the same shape.** `user` (id, email) plus `accessToken`, `refreshToken` and `expiresIn` in seconds
- **Refresh is single use and client bound.** The old token is revoked in the same operation that issues the new pair, and a refresh token never crosses to another client. Replaying a used token revokes every session the user has
- **OAuth codes are single use.** 60 seconds, consumed atomically, bound to the client, the redirect URI and the PKCE challenge they were issued with
- **OAuth transactions are sealed and single use.** The platform state is encrypted, tamper evident, expires after 10 minutes, is bound to the provider it was started for and its nonce is consumed on first presentation, so a state can never complete two callbacks. An application may pass its own one-time `state` at initiation and it is echoed on every callback redirect, success or error, for login CSRF protection on the consumer side
- **PKCE is required for public clients and supported for confidential ones.** A code issued with a challenge is only redeemable with the matching verifier regardless of client type
- **Only verified provider emails create or link accounts.** A GitHub account with no verified email is refused, so OAuth cannot be used to squat on someone else's address

## What consumers may assume

- Login rate limits are two layered: 5 attempts per minute per account per client per IP and 30 per minute per IP in total, with `X-RateLimit-*` headers on responses. Register and the password flows allow 5 per minute per IP
- Registering an existing email answers `EMAIL_EXISTS` (409). Emails are compared case insensitively and stored lowercased
- A user created through OAuth has no password until they set one through the reset flow, and logging in with a password against such an account fails as `INVALID_CREDENTIALS`, not as a distinguishable state
- Signing in with OAuth for an email that already has a password account links the provider to that account. A second, different provider identity for the same email is refused
- Expected OAuth failures land at the registered callback, not as dead end JSON in the user's browser. The redirect carries a stable `error` value: the provider's own code (for example `access_denied`), `exchange_failed`, `profile_failed`, `email_unverified`, `account_mismatch` or `account_inactive`, plus the echoed consumer `state`. Raw upstream responses never travel to the application

## When this can change

The response shape, the uniform error behavior and the single use rules are stable API. Rate limit numbers are operational tuning and may change without a major announcement, the two layer structure itself will not. New authentication methods (MFA is on the roadmap) will arrive as additional proofs, not as changes to the existing ones.
