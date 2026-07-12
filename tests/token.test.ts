import { describe, it, expect } from "vitest";
import { SignJWT, importPKCS8 } from "jose";
import { verifyAccessToken } from "../src/services/token";

function normalizePem(value: string): string {
  return value.replace(/\\n/g, "\n").trim();
}

const issuer = () => new URL(process.env.SERVICE_URL!).hostname;

async function signWithKid(kid: string): Promise<string> {
  const key = await importPKCS8(
    normalizePem(process.env.JWT_PRIVATE_KEY!),
    "EdDSA"
  );
  return new SignJWT({
    sub: "00000000-0000-0000-0000-000000000001",
    cid: "00000000-0000-0000-0000-000000000002",
    email: "kid-test@example.com",
    permissions: [],
  })
    .setProtectedHeader({ alg: "EdDSA", kid })
    .setIssuer(issuer())
    .setAudience("cl_kid_test_audience")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(key);
}

describe("platform verification is kid agnostic", () => {
  // The platform selects its verification key from configuration, not
  // from the token header, so a kid change alone never invalidates
  // tokens at the platform. The disruption of a kid change is entirely
  // consumer side (docs/operations/key-rotation.md).
  it("verifies a token whose header carries a different kid", async () => {
    const token = await signWithKid("some-other-kid-v9");

    const payload = await verifyAccessToken(token, "cl_kid_test_audience");
    expect(payload.email).toBe("kid-test@example.com");
  });

  it("verifies a token carrying the configured kid, same key", async () => {
    const token = await signWithKid(process.env.JWT_KEY_ID!);

    const payload = await verifyAccessToken(token, "cl_kid_test_audience");
    expect(payload.sub).toBe("00000000-0000-0000-0000-000000000001");
  });
});

import { env } from "../src/utils/env";

async function signHs256(): Promise<string> {
  const key = new TextEncoder().encode(process.env.JWT_SECRET!);
  return new SignJWT({
    sub: "00000000-0000-0000-0000-000000000003",
    cid: "00000000-0000-0000-0000-000000000004",
    email: "hs256-test@example.com",
    permissions: [],
  })
    .setProtectedHeader({ alg: "HS256", kid: "legacy-hs256" })
    .setIssuer(issuer())
    .setAudience("cl_hs256_audience")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(key);
}

describe("legacy HS256 acceptance (FUP-06)", () => {
  // The test env configures asymmetric keys, so HS256 is legacy-only
  // and gated behind ALLOW_LEGACY_HS256, which defaults off.
  it("rejects HS256 by default", async () => {
    (env as { ALLOW_LEGACY_HS256: boolean }).ALLOW_LEGACY_HS256 = false;
    const token = await signHs256();
    await expect(
      verifyAccessToken(token, "cl_hs256_audience")
    ).rejects.toThrow(/HS256 tokens are not accepted/);
  });

  it("accepts HS256 when explicitly enabled", async () => {
    (env as { ALLOW_LEGACY_HS256: boolean }).ALLOW_LEGACY_HS256 = true;
    try {
      const token = await signHs256();
      const payload = await verifyAccessToken(token, "cl_hs256_audience");
      expect(payload.email).toBe("hs256-test@example.com");
    } finally {
      (env as { ALLOW_LEGACY_HS256: boolean }).ALLOW_LEGACY_HS256 = false;
    }
  });
});
