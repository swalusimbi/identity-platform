# ADR 0005: Email links come from registered URLs, never from request input

Status: accepted

This one closes a phishing vector an early design left open.

## Context

Password reset and email verification mails contain a link the user is told to click. The first design took the link's base URL from the request body: the calling app knew its own reset page, so it sent `resetUrl` along with the email address and the platform appended the token.

That was fine while every client was confidential, because only a backend holding the client secret could trigger mails at all. Public clients broke the assumption. A public client id is not a secret, it ships in the SPA bundle. With request supplied URLs, anyone who read the id out of the bundle could call `POST /auth/password/forgot` with a victim's email and `resetUrl` pointing at their own domain. The victim receives a completely legitimate email, sent by the real platform, correctly worded for the real application, whose link leads to an attacker page with a valid reset token in the query string. The platform had been turned into a phishing relay that signs its own bait.

## Decision

Link targets are configuration, not input. Each client carries `passwordResetUrl` and `emailVerifyUrl`, settable only through the admin key protected client API. The mail flows read the URL from the client record and refuse with an explicit 400 `RESET_URL_NOT_CONFIGURED` when it is missing (`src/routes/account.ts`). Request input never chooses where a token lands.

The explicit 400 is safe precisely because it is a configuration statement, not an account statement. The account probing surface stays closed: when the URL is configured, forgot and send verification answer 200 whether or not the account exists.

## Consequences

- A public client id alone can still trigger a reset mail for a known address, but the link inside goes where the operator registered, so the mail is useless as bait
- Registering a client that uses the mail flows now has a required setup step, and tenant bootstrap refuses to invite an admin until `passwordResetUrl` is set, because the invite links there
- Changing a reset page URL is an operator action with an audit trail (once audit lands) instead of an invisible per request choice

## Alternatives considered

- **Allow list of URL prefixes per client, request picks within it**: rejected, all cost of registration with extra matching logic to get wrong, and no real flexibility win over one registered URL per purpose
- **Only give tokens to confidential clients**: rejected, public clients legitimately need password flows, that is what they are for
