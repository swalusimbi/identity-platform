# Getting Started

Integrate a real application with the platform in about ten minutes. Everything below was executed against a fresh checkout, the outputs are real.

You will run the platform with one command, register an application, protect its routes with locally verified tokens and finish with role based permissions actually gating a request.

## 1. Run the platform

```bash
git clone <repo-url> && cd identity-platform
docker compose up
```

That is the whole setup. The stack brings up Postgres and Redis, applies the schema migrations, generates a development signing key pair on first boot and starts the platform:

```
platform-1  | ✓ Migrations applied
platform-1  | ✓ Redis connected
platform-1  | ✓ Identity Platform running on port 5300
```

Three URLs worth opening before writing any code:

| URL | What it is |
|---|---|
| http://localhost:5300/health | `{"status":"ok","redis":"ok","database":"ok"}` |
| http://localhost:5300/docs | Browsable API reference over the live spec |
| http://localhost:5300/.well-known/jwks.json | The public signing key your app will verify tokens with |

Every credential in `docker-compose.yml` is a local development throwaway. The admin key is `local-dev-admin-key`.

## 2. Register your application

Every application is a client. Register one:

```bash
curl -X POST localhost:5300/clients \
  -H "X-Admin-Key: local-dev-admin-key" \
  -H "Content-Type: application/json" \
  -d '{"name": "My First App", "passwordResetUrl": "http://localhost:4000/reset-password"}'
```

```json
{
  "id": "683e0eaa-bd04-49ff-857a-e6fd44fa13f2",
  "name": "My First App",
  "clientId": "cl_GHfvc5m9MRlJsMbyzIGWIQ",
  "clientSecret": "cs_SP_gH0JifkbMYdOs9EXwD77q9gcIrcc6D7yyOVSITkg",
  "warning": "Store the client secret securely. It cannot be retrieved again."
}
```

The warning means it: the secret is stored only as a hash and this response is the one time you will ever see it. Keep both values, they go into your app's environment. The `passwordResetUrl` registers where emailed links may point, request input never chooses that (see [ADR 0005](adr/0005-registered-email-link-urls.md)), and the admin invite in step 5 needs it.

## 3. Integrate an application

A minimal Express app. The SDK is a single file you vendor, its only dependency is `jose`:

```bash
mkdir my-notes-api && cd my-notes-api
npm init -y
npm install express jose
npm install -D tsx typescript @types/express @types/node
mkdir -p src/lib
cp ../identity-platform/sdk/auth-client.ts src/lib/
```

`src/index.ts`:

```ts
import express from "express";
import {
  createAuthClient,
  requirePermission,
  AuthApiError,
  AuthTransportError,
} from "./lib/auth-client";

const auth = createAuthClient({
  serviceUrl: "http://localhost:5300",
  clientId: process.env.AUTH_CLIENT_ID!,
  clientSecret: process.env.AUTH_CLIENT_SECRET!,
});

const app = express();
app.use(express.json());

// Your app's own signup and login, identity delegated to the platform.
// No try/catch here: Express 5 routes rejected promises to the error
// middleware below, which answers with the real failure.
app.post("/signup", async (req, res) => {
  const tokens = await auth.register(req.body.email, req.body.password);
  res.status(201).json(tokens);
});

app.post("/login", async (req, res) => {
  const tokens = await auth.login(req.body.email, req.body.password);
  res.json(tokens);
});

// Protected: any signed in user
const notes = new Map<string, string[]>();
app.get("/notes", auth.requireAuth, (req, res) => {
  res.json({ owner: req.user!.email, notes: notes.get(req.user!.id) ?? [] });
});

app.post("/notes", auth.requireAuth, (req, res) => {
  const mine = notes.get(req.user!.id) ?? [];
  mine.push(req.body.text);
  notes.set(req.user!.id, mine);
  res.status(201).json({ count: mine.length });
});

// Protected: requires a specific permission
app.delete("/notes", auth.requireAuth, requirePermission("notes:purge"), (req, res) => {
  notes.delete(req.user!.id);
  res.json({ message: "All notes purged" });
});

// One place turns platform failures into honest responses. Never
// flatten everything to 401: a rate limited user is not unauthorized
app.use((err: unknown, req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (err instanceof AuthApiError) {
    res.status(err.status).json({
      error: err.message,
      code: err.code,
      ...(err.details ? { details: err.details } : {}),
      ...(err.rateLimit?.resetAt ? { retryAt: err.rateLimit.resetAt.toISOString() } : {}),
    });
    return;
  }
  if (err instanceof AuthTransportError) {
    res.status(502).json({ error: "Authentication is temporarily unavailable" });
    return;
  }
  next(err);
});

app.listen(4000, () => console.log("my-notes-api on http://localhost:4000"));
```

With that middleware in place your app forwards what actually happened: a wrong password is `401 INVALID_CREDENTIALS`, a malformed email is `400 VALIDATION_ERROR` with field details, the sixth rapid login attempt is `429` with a `retryAt` timestamp from the platform's rate limit headers and a platform outage is a `502` instead of a mysterious hang, bounded by the SDK's 10 second request timeout.

Run it with the credentials from step 2:

```bash
AUTH_CLIENT_ID=cl_... AUTH_CLIENT_SECRET=cs_... npx tsx src/index.ts
```

`requireAuth` verifies Bearer tokens **locally**. It contacts the platform in exactly three cases: fetching the JWKS when its cache is cold or a token carries an unknown key id, and calling `/auth/verify` for legacy HS256 tokens or when JWKS itself is unavailable. Ordinary requests, valid or invalid, never leave your process, so protected routes keep working even if the platform is briefly down. Note that the SDK never refreshes tokens on its own, your app calls `refreshToken` when it sees a 401.

## 4. Sign up and call the protected routes

```bash
curl -X POST localhost:4000/signup -H "Content-Type: application/json" \
  -d '{"email":"ada@example.com","password":"correct-horse-battery"}'
# {"user":{"id":"11d9...","email":"ada@example.com"},"accessToken":"eyJ...","refreshToken":"...","expiresIn":900}

curl localhost:4000/notes
# {"error":"Missing authorization header"}

TOKEN=<accessToken from signup>

curl -X POST localhost:4000/notes -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"text":"integrate the platform"}'
# {"count":1}

curl localhost:4000/notes -H "Authorization: Bearer $TOKEN"
# {"owner":"ada@example.com","notes":["integrate the platform"]}
```

The access token lives 15 minutes, `expiresIn` says so in seconds. Each refresh token is single use and rotation hands you a new one:

```ts
const operationId = auth.createRefreshOperationId();
const next = await auth.refreshToken(refreshToken, operationId);
```

Keep the operation id until the result is known. If transport fails before a response arrives, retry the old refresh token with the same operation id. Serialize refresh work per session and replace the stored token pair atomically.

## 5. Permissions

Try the purge:

```bash
curl -X DELETE localhost:4000/notes -H "Authorization: Bearer $TOKEN"
# {"error":"Missing permission: notes:purge"}
```

Ada has no roles yet. Permission management needs an administrator, and a fresh tenant gets its first one through bootstrap:

```bash
curl -X POST localhost:5300/clients/<client-uuid>/bootstrap \
  -H "X-Admin-Key: local-dev-admin-key" \
  -H "Content-Type: application/json" \
  -d '{"adminEmail":"admin@example.com"}'
```

This creates the management role (users, roles, api-keys and service-accounts, read and write) and emails the admin a set password link. Locally the mailer is `console`, so the "email" lands in the platform logs:

```bash
docker compose logs platform | grep reset-password
# Set your password here (valid for 24 hours): http://localhost:4000/reset-password?token=I3IoMHeX...
```

Set the admin's password with that token and log in:

```bash
curl -X POST localhost:5300/auth/password/reset -H "Content-Type: application/json" \
  -d '{"token":"I3IoMHeX...","newPassword":"admin-pass-123","clientId":"cl_...","clientSecret":"cs_..."}'
# {"message":"Password reset"}
```

Now, as the admin (use their `accessToken` from a normal login), create the permission, a role carrying it and assign it to Ada:

```bash
curl -X POST localhost:5300/roles/permissions -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"resource":"notes","action":"purge","description":"Delete all notes"}'

curl -X POST localhost:5300/roles -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"librarian","permissionIds":["<permission-id>"]}'

curl -X POST localhost:5300/roles/assign -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"userId":"<ada-user-id>","roleId":"<role-id>"}'
```

Permissions travel inside tokens, so Ada picks the grant up on her next login or refresh, at most one access token lifetime later. Log in again and the same request flips:

```bash
# fresh login, the token now carries the permission
# {"email": "ada@example.com", "permissions": ["notes:purge"]}

curl -X DELETE localhost:4000/notes -H "Authorization: Bearer $TOKEN"
# {"message":"All notes purged"}
```

That staleness bound is the platform's central deliberate tradeoff, documented in [contracts/sessions-and-tokens.md](contracts/sessions-and-tokens.md).

## Your second application

Register another client and repeat step 3, that is the whole procedure. Isolation is automatic: the new client gets its own users, roles, permissions and keys, and `ada@example.com` signing up there is a different account with a different password. Nothing about your first app changes. When applications should eventually share users, that is the user pools item on the [roadmap](../ROADMAP.md), designed so today's isolated setup migrates without config changes.

## Running without Docker

If you prefer the platform under your own node for development:

```bash
docker compose up -d postgres redis      # just the dependencies
cp .env.example .env
# in .env: DATABASE_URL=postgresql://identity:identity@localhost:5432/identity_platform
#          REDIS_URL=redis://localhost:6379/0
#          JWT_SECRET and ADMIN_KEY: any long values
sh scripts/dev-keys.sh >> .env           # appends a fresh signing pair
npm install
npm run db:migrate
npm run dev
```

## Troubleshooting, from actually hitting these

| Symptom | Cause |
|---|---|
| `RESET_URL_NOT_CONFIGURED` on bootstrap or forgot password | The client has no registered `passwordResetUrl`. Set it at registration or `PATCH /clients/:id` |
| `REGISTRATION_DISABLED` on signup | The client was created with `allowUserRegistration: false`. Provision users through `POST /users` instead |
| 429 after a few signups | Register and the password flows allow 5 requests per minute per IP. Wait for the window or vary the source |
| `INVALID_CLIENT` everywhere | Wrong or missing client secret. Unknown client, inactive client and bad secret all return this one error on purpose |
| `port is already allocated` on compose up | Something on your machine already holds 5432, 6379 or 5300. Stop it or adjust the published ports in docker-compose.yml |
| Purge still 403 after assigning the role | The old token predates the grant. Permissions are baked in at issuance, log in or refresh to pick them up |

## Where next

- [/docs on your running instance](http://localhost:5300/docs) for every endpoint
- [contracts/](contracts/README.md) for what your app may rely on
- [trust-model.md](trust-model.md) for who can invoke what, proving what
- [AUTH-JWKS-INTEGRATION.md](AUTH-JWKS-INTEGRATION.md) to verify tokens without the SDK
