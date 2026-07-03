# Identity Platform JWKS Integration

The auth service now supports local JWT verification for consuming apps.

## What changed

- New access tokens are signed with Ed25519 / EdDSA when `JWT_PRIVATE_KEY` and `JWT_PUBLIC_KEY` are configured.
- Public verification keys are exposed at `GET /.well-known/jwks.json`.
- `POST /auth/verify` remains available for API keys, compatibility, diagnostics, and fallback verification.
- Legacy `HS256` access tokens are still accepted by the auth service during migration, but they cannot be verified locally by other apps.

## Generate signing keys

```bash
openssl genpkey -algorithm Ed25519 -out jwt-private.pem
openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem
```

Configure:

```env
JWT_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----
JWT_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----
JWT_KEY_ID=auth-service-v1
```

Keep `JWT_SECRET` configured. It is still used for OAuth state encryption and short-lived legacy token verification.

## Consuming apps

Use JWKS for normal bearer-token authentication. Cache the key set locally and verify JWT signatures in-process instead of calling `/auth/verify` on every request.

```ts
import { createRemoteJWKSet, jwtVerify, JWTPayload } from "jose";

const issuer = "auth.example.com";
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
  const { payload } = await jwtVerify(token, jwks, { issuer });
  const authPayload = payload as AuthPayload;

  return {
    id: authPayload.sub,
    clientId: authPayload.cid,
    email: authPayload.email,
    permissions: authPayload.permissions || [],
  };
}
```

For permission checks, use the `permissions` claim locally. Call `/auth/verify` only when handling API keys, when the local JWKS cache is cold and cannot refresh, or when you intentionally want centralized introspection.

## Migration order

1. Deploy auth-service with `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`, and `JWT_KEY_ID`.
2. Confirm `https://auth.example.com/.well-known/jwks.json` returns one public key.
3. Update consuming apps to verify bearer JWTs locally.
4. Keep `/auth/verify` for API-key verification and fallback paths.
