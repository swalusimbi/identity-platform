import { describe, it, expect } from "vitest";
import request from "supertest";
import { createLocalJWKSet, jwtVerify } from "jose";
import app from "../src/app";
import { createTestClient, registerTestUser } from "./helpers";

describe("JWKS", () => {
  it("publishes the EdDSA public key", async () => {
    const res = await request(app).get("/.well-known/jwks.json");

    expect(res.status).toBe(200);
    expect(res.headers["cache-control"]).toContain("max-age=300");
    expect(res.body.keys).toHaveLength(1);
    expect(res.body.keys[0]).toMatchObject({
      kty: "OKP",
      crv: "Ed25519",
      alg: "EdDSA",
      use: "sig",
      kid: process.env.JWT_KEY_ID,
    });
    // Never leak private key material
    expect(res.body.keys[0].d).toBeUndefined();
  });

  it("lets consumers verify access tokens locally, like the SDK does", async () => {
    const client = await createTestClient("jwks-app");
    const user = await registerTestUser(client, "jwks@example.com");

    const jwksRes = await request(app).get("/.well-known/jwks.json");
    const jwks = createLocalJWKSet(jwksRes.body);

    // Issuer defaults to the SERVICE_URL hostname
    const issuer = new URL(process.env.SERVICE_URL!).hostname;
    const { payload, protectedHeader } = await jwtVerify(
      user.accessToken,
      jwks,
      { issuer, audience: client.clientId }
    );

    expect(protectedHeader.alg).toBe("EdDSA");
    expect(payload.sub).toBe(user.id);
    expect(payload.cid).toBe(client.id);
    expect(payload.aud).toBe(client.clientId);
    expect(payload.email).toBe("jwks@example.com");
    expect(Array.isArray(payload.permissions)).toBe(true);
  });
});
