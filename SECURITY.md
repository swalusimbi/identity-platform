# Security Policy

## Reporting a vulnerability

Report privately through [GitHub's private vulnerability reporting](../../security/advisories/new) (the Security tab of this repository). Do not open a public issue for anything exploitable.

What helps: the affected endpoint or flow, a reproduction and your assessment of impact. You can expect an acknowledgment within 72 hours and either a fix or a concrete plan within 30 days. Coordinated disclosure is welcome, if you want to publish, agree on a date rather than surprising the deployments that run this.

## Supported versions

Development happens on a single track. The `main` branch is the supported version and there are no maintained release branches. A reported vulnerability is fixed at the tip and deployments update forward.

## Not vulnerabilities

Some behaviors that look like findings are documented decisions. Please read the linked reasoning before reporting them:

- **A revoked or deactivated user's access token keeps working for up to 15 minutes.** That is the platform's revocation window, the accepted price of offline verification. See [contracts/sessions-and-tokens.md](docs/contracts/sessions-and-tokens.md)
- **Rate limiting stops enforcing while Redis is down.** Fail open is a deliberate availability decision, see [ADR 0004](docs/adr/0004-fail-open-rate-limiting.md)
- **`POST /auth/password/forgot` sends email for any registered address given only a public client id.** The mail's link target is registered configuration, so this is noise, not phishing. See [ADR 0005](docs/adr/0005-registered-email-link-urls.md)
- **Refresh and account tokens are stored as unsalted SHA-256.** They are 256 bit random values, not passwords. Passwords themselves are argon2id. See the database disclosure section of the [threat model](docs/threat-model.md)
- **There is no MFA yet.** Known, on the roadmap, not a report

If you can break one of these decisions beyond its stated bounds (for example, extend the revocation window, or turn a registered link mail into an actual phish), that absolutely is a report and a welcome one.

## Scope notes for deployments

The platform assumes TLS at a reverse proxy, an `ADMIN_KEY` with real entropy, configured Ed25519 signing keys and `CORS_ORIGINS` set when browsers call it directly. A deployment missing those is misconfigured rather than the software being vulnerable, [operations/availability.md](docs/operations/availability.md) carries the checklist.
