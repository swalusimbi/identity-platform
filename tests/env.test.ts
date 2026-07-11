import { describe, it, expect } from "vitest";
import { parseEnv } from "../src/utils/env";

const base = {
  DATABASE_URL: "postgresql://user:pass@localhost:5432/identity_test",
  JWT_SECRET: "a-jwt-secret-that-is-at-least-32-chars",
  ADMIN_KEY: "an-admin-key",
};

const keys = {
  JWT_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\\nX\\n-----END PRIVATE KEY-----",
  JWT_PUBLIC_KEY: "-----BEGIN PUBLIC KEY-----\\nY\\n-----END PUBLIC KEY-----",
};

describe("environment guardrails", () => {
  it("allows development without signing keys, the HS256 fallback", () => {
    const env = parseEnv(base);
    expect(env.NODE_ENV).toBe("development");
  });

  it("refuses production without signing keys", () => {
    expect(() => parseEnv({ ...base, NODE_ENV: "production" })).toThrow(
      /required in production/
    );
  });

  it("allows production with the key pair configured", () => {
    const env = parseEnv({ ...base, NODE_ENV: "production", ...keys });
    expect(env.NODE_ENV).toBe("production");
  });

  it("refuses half a key pair in any environment", () => {
    expect(() =>
      parseEnv({ ...base, JWT_PRIVATE_KEY: keys.JWT_PRIVATE_KEY })
    ).toThrow(/configured together/);
  });
});
