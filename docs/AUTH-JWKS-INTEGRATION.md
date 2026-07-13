# Identity Platform JWKS Integration

The Identity Platform supports local JWT verification for consuming apps.

## What changed

- New access tokens are signed with Ed25519 / EdDSA when `JWT_PRIVATE_KEY` and `JWT_PUBLIC_KEY` are configured.
- Public verification keys are exposed at `GET /.well-known/jwks.json`.
- `POST /auth/verify` remains available for API keys, compatibility, diagnostics and fallback verification.
- Legacy `HS256` access tokens can be accepted during a controlled migration by setting `ALLOW_LEGACY_HS256=true` on the identity platform. They cannot be verified locally by other apps.

## Generate signing keys

```bash
openssl genpkey -algorithm Ed25519 -out jwt-private.pem
openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem
```

Configure:

```env
JWT_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----
JWT_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----
JWT_KEY_ID=identity-platform-v1
```

Keep `JWT_SECRET` configured. It is used for OAuth state encryption and, only when `ALLOW_LEGACY_HS256=true`, short-lived legacy token verification.

## Consuming apps

Use JWKS for normal bearer-token authentication. Cache the key set locally and verify JWT signatures in-process instead of calling `/auth/verify` on every request.

```ts
import { createRemoteJWKSet, jwtVerify, JWTPayload } from "jose";

const issuer = "auth.example.com";
const audience = process.env.AUTH_CLIENT_ID!;
const jwks = createRemoteJWKSet(
  new URL(`${process.env.AUTH_SERVICE_URL}/.well-known/jwks.json`),
  {
    cacheMaxAge: 5 * 60 * 1000,
    cooldownDuration: 30 * 1000,
  }
);

export interface AuthUser {
  id: string;
  clientId: string;
  email: string;
  permissions: string[];
}

interface AuthPayload extends JWTPayload {
  sub: string;
  cid: string;
  email: string;
  permissions?: string[];
}

export async function verifyJwtLocally(token: string): Promise<AuthUser> {
  const { payload } = await jwtVerify(token, jwks, { issuer, audience });
  const authPayload = payload as AuthPayload;

  return {
    id: authPayload.sub,
    clientId: authPayload.cid,
    email: authPayload.email,
    permissions: authPayload.permissions || [],
  };
}
```

The audience is the application's external `cl_...` client id. A token with a different audience belongs to another application and must be rejected even when its signature is valid.

For permission checks, use the `permissions` claim locally. Call `/auth/verify` only when handling API keys, when the local JWKS cache is cold and cannot refresh or when you intentionally want centralized introspection. Include the same client id as `audience` in every remote verification request.

## Migration order

1. Deploy the Identity Platform with `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY` and `JWT_KEY_ID`. Set `ALLOW_LEGACY_HS256=true` only if access tokens from the previous HS256 deployment may still be active.
2. Confirm `https://auth.example.com/.well-known/jwks.json` returns one public key.
3. Update consuming apps to verify bearer JWTs locally. A consumer that must accept the remaining legacy tokens creates its SDK client with `allowLegacyHs256: true`.
4. Wait at least one maximum access-token lifetime after EdDSA issuance begins. The default is 15 minutes.
5. Remove `ALLOW_LEGACY_HS256` from the platform and `allowLegacyHs256` from every consumer. New HS256 tokens are then rejected locally without a platform request.
6. Keep `/auth/verify` for API-key verification, diagnostics and JWKS outage fallback.
