# Contributing

Thanks for looking under the hood. This document describes how the repo actually works, everything in it is practiced, not aspirational.

## Getting a dev environment

```bash
docker compose up         
```

or for the platform under your own node, the [without Docker section](docs/getting-started.md#running-without-docker) of the getting started guide.

## Running the tests

The suite is integration tests against real Postgres and Redis, no mocks of either:

```bash
cp .env.test.example .env.test    # point it at a DISPOSABLE database
npm test
```

Two hard rules the setup enforces:

- The test database name must contain `test`, the runner refuses anything else
- The global setup pushes the schema, truncates every table and flushes the configured Redis DB. Never point `.env.test` at data you care about

The suite must be fully green before and after your change. A feature without tests covering its guarantees is not done.

## How changes are made here

**Contracts before code.** A capability that consumers will rely on gets its contract written first, in `docs/contracts/`, and the implementation follows the contract. The audit log and the sessions API were both built this way, their contract commits predate their code commits in the history.

**Decisions get ADRs.** Anything that chooses between real alternatives (a signing scheme, a failure mode, a thing deliberately not built) is recorded in `docs/adr/` with the alternatives that lost and the consequences accepted. If your change reverses an existing ADR, write the superseding one rather than silently contradicting it.

**Commits are per concern.** One commit changes one thing: the contract, the schema, the implementation, the docs surfacing. Look at any feature in `git log` for the pattern. Conventional prefixes are used loosely (`feat(scope):`, `fix:`, `docs:`, `test:`, `chore:`), lowercase, present tense.

**Docs ship with the change.** If behavior described in the README, a contract, a runbook or the OpenAPI spec changes, the same PR updates it. `docs/openapi.json` is the wire-level source of truth and is served live at `/openapi.json`, so a stale spec is a served lie.

## What fits this platform

The scope question every addition must answer, from the project's principles:

> Would another engineering team reasonably expect an identity platform to provide this?

Password policies, sessions, tokens, roles, machine credentials, audit: yes. Profile photos, org charts, app specific preferences, domain authorization: no, consuming applications own those. When unsure, check [ROADMAP.md](ROADMAP.md), additions that fit a named phase are much easier to land.

Backward compatibility is a feature. Existing consumers must keep working across your change, the contracts say what may not break and `docs/contracts/README.md` describes how breaking changes are announced when they are unavoidable.

## Style

- Match the surrounding code, the repo is small enough to have one voice
- Comments state constraints the code cannot show, not narration of the next line
- In prose (docs, error messages, anything a person reads): plain punctuation and short declarative sentences
- Real numbers over adjectives. "5 attempts per minute" beats "strictly rate limited"

## Security issues

Never through issues or PRs. See [SECURITY.md](SECURITY.md) for private reporting, and read its "not vulnerabilities" list first, several deliberate tradeoffs look like findings at first glance.
