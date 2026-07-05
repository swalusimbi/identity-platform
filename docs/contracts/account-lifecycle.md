# Contract: Account Lifecycle

Everything that happens to an account after it exists: invites, password reset, email verification, password change and deactivation. The common thread is single use emailed tokens and immediate session revocation.

## Who invokes

- The mail requesting endpoints (`/auth/password/forgot`, `/auth/email/send-verification`) and the consuming endpoints (`/auth/password/reset`, `/auth/email/verify`): application backends with client credentials, on behalf of a user who may not be signed in
- `POST /auth/password/change`: the signed in user themselves, with their Bearer token
- Provisioning (`POST /users`), listing (`GET /users`) and deactivation (`PATCH /users/:id`): a principal inside the client holding `users:write` (or `users:read` for listing)

## The emailed token rules

One mechanism backs resets, verification and invites. Its guarantees:

| Rule | Detail |
|---|---|
| Single use | Consumed atomically, a second use fails no matter how fast |
| Purpose bound | A reset token cannot verify an email and vice versa |
| Client bound | A token consumed through the wrong client fails |
| Uniform failure | Unknown, expired, used and wrong purpose all return the same error, tokens cannot be probed |
| Hashed at rest | Only the SHA-256 of the token is stored, the raw value exists in the email link alone |
| Lifetimes | Reset 1 hour, verification 24 hours, invites 24 hours |
| Registered targets | Links are built exclusively from the client's registered URLs ([ADR 0005](../adr/0005-registered-email-link-urls.md)) |

## What is guaranteed

- **Account existence is never disclosed.** Forgot and send verification answer 200 with the same message whether or not the account exists. The only 400 they emit is `RESET_URL_NOT_CONFIGURED` (or the verify equivalent), which states configuration, not accounts
- **A completed reset is a security event, not just a password update.** It revokes every refresh token the user has and marks the email verified, because completing it proved control of the mailbox. Outstanding access tokens ride out the at most 15 minute window ([sessions-and-tokens.md](sessions-and-tokens.md))
- **Password change requires the current password even with a valid token** and also revokes all sessions. A stolen access token alone cannot quietly take over the account by rotating its password
- **OAuth only accounts fail closed on password paths.** An account created through Google or GitHub has no password. Password login against it is `INVALID_CREDENTIALS` and password change directs to the reset flow (`PASSWORD_NOT_SET`), which is also the supported way to add a password to such an account
- **Provisioned users start passwordless.** `POST /users` creates the account and, unless `sendInvite: false` (for accounts that will only ever use OAuth), emails a 24 hour set password link. Until the link is used nobody can log in as that user
- **Deactivation is the offboarding switch.** `PATCH /users/:id` with `isActive: false` blocks login, refresh and every token flow immediately and revokes all refresh tokens. Reactivation is the same call with `true`, the account's data, roles and password survive deactivation untouched

## What consumers may assume

- Email uniqueness is per client (`users_client_email_idx`). The same address on two clients is two accounts with independent passwords and lifecycles
- The mail requesting endpoints are rate limited to 5 per minute per IP, so a UI should debounce its resend button rather than expect unlimited retries
- Role assignment at provisioning validates ownership: `roleIds` naming another client's roles fail as `UNKNOWN_ROLE` and the user is not created
- Mail delivery is synchronous today. If SMTP is down the requesting call fails rather than silently dropping the mail, so surfacing the error to the user and retrying is correct client behavior

## When this can change

Single use, purpose binding, uniform failures and the always 200 rule are stable API. Token lifetimes (1 and 24 hours) are policy and could be tuned per deployment in the future, but only downward pressure is plausible. The sessions API ([sessions-and-tokens.md](sessions-and-tokens.md)) lets users list and revoke individual sessions without changing the revoke everything semantics of reset, change and deactivation.
