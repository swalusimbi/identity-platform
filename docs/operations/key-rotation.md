# Operations: Key Rotation

The platform holds four secrets an operator may need to rotate. Only one of them, the signing key, has consumer visible mechanics. This runbook covers all four, the routine procedure and the compromise procedure.

## The signing key (Ed25519)

JWKS publishes a single key, so rotation is a swap rather than an overlap.

### Routine rotation

1. Generate a new pair:

   ```bash
   openssl genpkey -algorithm Ed25519 -out jwt-private.pem
   openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem
   ```

2. Update `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY` and bump `JWT_KEY_ID` (for example `identity-platform-v1` to `identity-platform-v2`). The `kid` bump is not cosmetic, it is what tells consumers a new key exists
3. Restart the service

### What consumers experience

Access tokens signed by the old key fail verification from the restart until they would have expired anyway, at most one access token lifetime (15 minutes by default). The SDK does not refresh on its own: recovery relies on the application refreshing when it sees a 401, the standard pattern, after which the refresh returns a token signed by the new key. Refresh tokens are opaque database state and are untouched by rotation.

The SDK's JWKS client fetches keys by `kid` and refetches the key set when it sees an unfamiliar one, so the new key propagates on first contact. The JWKS response is cacheable for 300 seconds, which only delays consumers that ignore `kid` and blindly cache, the SDK is not among them.

Rotate during low traffic if the brief burst of forced refreshes matters to you.

### Compromise rotation

If the private key may have been exposed, the swap alone is not enough, because the attacker can mint tokens until the restart and hold refresh capable sessions afterward. Do both:

1. Rotate as above, immediately, off schedule
2. Revoke every active session so all outstanding refresh tokens die:

   ```sql
   UPDATE refresh_tokens SET revoked = true WHERE revoked = false;
   ```

Every user logs in again. That is the point: after the revocation plus one access token lifetime, nothing the attacker holds works.

### Changing the kid without changing the key

Do not. A `kid` change alone has the consumer facing blast radius of a full rotation with none of the benefit: JWKS stops publishing the old id, consumers fail local verification of every in flight token as a definitive 401 (the SDK does not fall back for unknown key ids) and every session is forced through a refresh within one access token lifetime. The platform itself keeps verifying old tokens because it selects the key from configuration, not from the token header, so the disruption is entirely at the consumers.

The policy this implies: the `kid`, including its code default, only ever changes as part of an intentional signing key rotation. Deployments that pin `JWT_KEY_ID` in their environment are immune to default changes either way, which is one more reason to pin it.

## The admin key

`ADMIN_KEY` guards client registration and tenant management. Rotation is an environment change plus restart, nothing consumer visible depends on it. Rotate it like any shared secret: on operator turnover and on any suspicion. Choose a long random value, the comparison is constant time but entropy is your job.

## Client secrets

Rotated per client through the API, no restart involved:

```bash
curl -X POST https://auth.example.com/clients/<uuid>/rotate-secret \
  -H "X-Admin-Key: $ADMIN_KEY"
```

The old secret stops working in the same operation that mints the new one, so coordinate with the application's redeploy. The new secret is shown once in the response and stored only as a hash, exactly like at registration.

## JWT_SECRET (legacy and state encryption)

`JWT_SECRET` no longer signs new tokens once Ed25519 keys are configured, but it still does two jobs: verifying leftover legacy HS256 tokens and deriving the AES-256-GCM key that encrypts OAuth state. Rotating it therefore:

- Invalidates any in flight OAuth sign in, a 10 minute blast radius at most (state expires after 10 minutes anyway)
- Kills any legacy HS256 access tokens still circulating, at most one access token lifetime of disruption

Both effects are self healing, users retry the sign in or refresh. Safe to rotate whenever, just not mid incident while you are also debugging OAuth.
