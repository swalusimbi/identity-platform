import { describe, it, expect, beforeAll, vi } from "vitest";
import request from "supertest";
import { createHash, randomBytes } from "crypto";
import app from "../src/app";
import {
  encryptState,
  decryptState,
  generateAuthCode,
  storeAuthCode,
  consumeAuthCode,
  verifierMatchesChallenge,
} from "../src/services/oauth";
import {
  createTestClient,
  refreshOperationId,
  registerTestUser,
  TestClient,
  TestUser,
} from "./helpers";

const ADMIN_KEY = process.env.ADMIN_KEY!;
const REDIRECT_URI = "https://app.example.com/auth/callback";

describe("OAuth state parameter", () => {
  it("round-trips through encrypt/decrypt", () => {
    const state = {
      clientId: "cl_abc",
      redirectUri: REDIRECT_URI,
      nonce: "nonce-1",
    };
    expect(decryptState(encryptState(state))).toMatchObject(state);
  });

  it("rejects expired state", () => {
    vi.useFakeTimers();
    try {
      const encrypted = encryptState({
        clientId: "cl_abc",
        redirectUri: REDIRECT_URI,
        nonce: "nonce-exp",
      });
      vi.advanceTimersByTime(11 * 60 * 1000);
      expect(() => decryptState(encrypted)).toThrow(/expired/i);
    } finally {
      vi.useRealTimers();
    }
  });

  it("rejects tampered state", () => {
    const encrypted = encryptState({
      clientId: "cl_abc",
      redirectUri: REDIRECT_URI,
      nonce: "nonce-2",
    });
    const [iv, tag, ciphertext] = encrypted.split(".");
    const flipped =
      ciphertext[0] === "A" ? `B${ciphertext.slice(1)}` : `A${ciphertext.slice(1)}`;
    expect(() => decryptState(`${iv}.${tag}.${flipped}`)).toThrow();
  });
});

describe("authorization codes", () => {
  it("can be consumed exactly once", async () => {
    const code = generateAuthCode();
    const data = {
      userId: "user-1",
      clientId: "internal-uuid",
      appClientId: "cl_abc",
      redirectUri: REDIRECT_URI,
    };

    await storeAuthCode(code, data);
    expect(await consumeAuthCode(code)).toEqual(data);
    expect(await consumeAuthCode(code)).toBeNull();
  });

  it("returns null for unknown codes", async () => {
    expect(await consumeAuthCode("never-stored")).toBeNull();
  });
});

describe("GET /auth/oauth/:provider (initiate)", () => {
  let client: TestClient;

  beforeAll(async () => {
    const res = await request(app)
      .post("/clients")
      .set("X-Admin-Key", ADMIN_KEY)
      .send({ name: "oauth-initiate-app", redirectUris: [REDIRECT_URI] });
    client = {
      id: res.body.id,
      clientId: res.body.clientId,
      clientSecret: res.body.clientSecret,
    };
  });

  it("redirects to the provider with an encrypted state", async () => {
    const res = await request(app).get("/auth/oauth/google").query({
      client_id: client.clientId,
      redirect_uri: REDIRECT_URI,
    });

    expect(res.status).toBe(302);
    const url = new URL(res.headers.location);
    expect(url.hostname).toBe("accounts.google.com");
    expect(url.searchParams.get("redirect_uri")).toBe(
      `${process.env.SERVICE_URL}/auth/oauth/google/callback`
    );

    const state = decryptState(url.searchParams.get("state")!);
    expect(state.clientId).toBe(client.clientId);
    expect(state.redirectUri).toBe(REDIRECT_URI);
    expect(state.nonce).toBeTruthy();
  });

  it("rejects an unregistered redirect_uri", async () => {
    const res = await request(app).get("/auth/oauth/google").query({
      client_id: client.clientId,
      redirect_uri: "https://evil.example.com/steal",
    });
    expect(res.status).toBe(400);
  });

  it("rejects clients that have no registered redirect URIs", async () => {
    const bare = await createTestClient("oauth-no-uris-app");
    const res = await request(app).get("/auth/oauth/google").query({
      client_id: bare.clientId,
      redirect_uri: REDIRECT_URI,
    });
    expect(res.status).toBe(400);
  });

  it("rejects an unknown client_id", async () => {
    const res = await request(app).get("/auth/oauth/google").query({
      client_id: "cl_does_not_exist",
      redirect_uri: REDIRECT_URI,
    });
    expect(res.status).toBe(400);
  });

  it("rejects an unsupported provider with a 400", async () => {
    const res = await request(app).get("/auth/oauth/myspace").query({
      client_id: client.clientId,
      redirect_uri: REDIRECT_URI,
    });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe("UNSUPPORTED_PROVIDER");
  });
});

describe("POST /auth/oauth/token (code exchange)", () => {
  let client: TestClient;
  let user: TestUser;

  beforeAll(async () => {
    client = await createTestClient("oauth-token-app");
    user = await registerTestUser(client, "oauth-user@example.com");
  });

  async function storeCodeForUser(): Promise<string> {
    const code = generateAuthCode();
    await storeAuthCode(code, {
      userId: user.id,
      clientId: client.id,
      appClientId: client.clientId,
      redirectUri: REDIRECT_URI,
    });
    return code;
  }

  it("exchanges a valid code for a token pair", async () => {
    const code = await storeCodeForUser();

    const res = await request(app).post("/auth/oauth/token").send({
      code,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      redirectUri: REDIRECT_URI,
    });

    expect(res.status).toBe(200);
    expect(res.body.user.id).toBe(user.id);
    expect(res.body.accessToken).toBeTruthy();
    expect(res.body.refreshToken).toBeTruthy();
  });

  it("rejects code replay", async () => {
    const code = await storeCodeForUser();
    const body = {
      code,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      redirectUri: REDIRECT_URI,
    };

    const first = await request(app).post("/auth/oauth/token").send(body);
    expect(first.status).toBe(200);

    const replay = await request(app).post("/auth/oauth/token").send(body);
    expect(replay.status).toBe(401);
    expect(replay.body.code).toBe("INVALID_CODE");
  });

  it("rejects a code issued to a different client", async () => {
    const code = await storeCodeForUser();
    const other = await createTestClient("oauth-other-app");

    const res = await request(app).post("/auth/oauth/token").send({
      code,
      clientId: other.clientId,
      clientSecret: other.clientSecret,
      redirectUri: REDIRECT_URI,
    });
    expect(res.status).toBe(401);
    expect(res.body.code).toBe("CLIENT_MISMATCH");

    const rightful = await request(app).post("/auth/oauth/token").send({
      code,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      redirectUri: REDIRECT_URI,
    });
    expect(rightful.status).toBe(200);
  });

  it("rejects a wrong client secret", async () => {
    const code = await storeCodeForUser();

    const res = await request(app).post("/auth/oauth/token").send({
      code,
      clientId: client.clientId,
      clientSecret: "cs_wrong",
      redirectUri: REDIRECT_URI,
    });
    expect(res.status).toBe(401);

    const rightful = await request(app).post("/auth/oauth/token").send({
      code,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      redirectUri: REDIRECT_URI,
    });
    expect(rightful.status).toBe(200);
  });

  it("rejects a redirect_uri mismatch", async () => {
    const code = await storeCodeForUser();

    const res = await request(app).post("/auth/oauth/token").send({
      code,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      redirectUri: "https://app.example.com/other-callback",
    });
    expect(res.status).toBe(401);

    const rightful = await request(app).post("/auth/oauth/token").send({
      code,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      redirectUri: REDIRECT_URI,
    });
    expect(rightful.status).toBe(200);
  });
});

describe("public clients and PKCE", () => {
  let publicClient: TestClient;
  let user: TestUser;

  const verifier = randomBytes(48).toString("base64url"); // 64 chars
  const challenge = createHash("sha256").update(verifier).digest("base64url");

  beforeAll(async () => {
    publicClient = await createTestClient("pkce-spa-app", {
      isPublic: true,
      redirectUris: [REDIRECT_URI],
    });
    user = await registerTestUser(publicClient, "pkce-user@example.com");
  });

  it("creates public clients without a secret", () => {
    expect(publicClient.clientSecret).toBeUndefined();
  });

  it("matches verifiers to challenges per RFC 7636", () => {
    expect(verifierMatchesChallenge(verifier, challenge)).toBe(true);
    expect(verifierMatchesChallenge("a".repeat(43), challenge)).toBe(false);
  });

  it("allows login and refresh without a secret", async () => {
    const login = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", "10.98.0.1")
      .send({
        email: user.email,
        password: user.password,
        clientId: publicClient.clientId,
      });
    expect(login.status).toBe(200);

    const refresh = await request(app).post("/auth/refresh").send({
      refreshToken: login.body.refreshToken,
      clientId: publicClient.clientId,
      operationId: refreshOperationId(),
    });
    expect(refresh.status).toBe(200);
  });

  it("still requires the secret for confidential clients", async () => {
    const confidential = await createTestClient("pkce-confidential-app");
    const res = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", "10.98.0.2")
      .send({
        email: "whoever@example.com",
        password: "irrelevant-pw",
        clientId: confidential.clientId,
      });
    expect(res.status).toBe(401);
    expect(res.body.code).toBe("INVALID_CLIENT");
  });

  it("requires a code_challenge to initiate OAuth", async () => {
    const res = await request(app).get("/auth/oauth/google").query({
      client_id: publicClient.clientId,
      redirect_uri: REDIRECT_URI,
    });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe("PKCE_REQUIRED");
  });

  it("carries the challenge through state when initiating", async () => {
    const res = await request(app).get("/auth/oauth/google").query({
      client_id: publicClient.clientId,
      redirect_uri: REDIRECT_URI,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    expect(res.status).toBe(302);

    const url = new URL(res.headers.location);
    const state = decryptState(url.searchParams.get("state")!);
    expect(state.codeChallenge).toBe(challenge);
  });

  async function storePkceCode(): Promise<string> {
    const code = generateAuthCode();
    await storeAuthCode(code, {
      userId: user.id,
      clientId: publicClient.id,
      appClientId: publicClient.clientId,
      redirectUri: REDIRECT_URI,
      codeChallenge: challenge,
    });
    return code;
  }

  it("exchanges a code with the correct verifier and no secret", async () => {
    const code = await storePkceCode();

    const res = await request(app).post("/auth/oauth/token").send({
      code,
      clientId: publicClient.clientId,
      redirectUri: REDIRECT_URI,
      codeVerifier: verifier,
    });

    expect(res.status).toBe(200);
    expect(res.body.user.id).toBe(user.id);
    expect(res.body.accessToken).toBeTruthy();
  });

  it("rejects a wrong verifier", async () => {
    const code = await storePkceCode();

    const res = await request(app).post("/auth/oauth/token").send({
      code,
      clientId: publicClient.clientId,
      redirectUri: REDIRECT_URI,
      codeVerifier: randomBytes(48).toString("base64url"),
    });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe("INVALID_VERIFIER");

    const rightful = await request(app).post("/auth/oauth/token").send({
      code,
      clientId: publicClient.clientId,
      redirectUri: REDIRECT_URI,
      codeVerifier: verifier,
    });
    expect(rightful.status).toBe(200);
  });

  it("rejects a missing verifier when the code carries a challenge", async () => {
    const code = await storePkceCode();

    const res = await request(app).post("/auth/oauth/token").send({
      code,
      clientId: publicClient.clientId,
      redirectUri: REDIRECT_URI,
    });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe("INVALID_VERIFIER");

    const rightful = await request(app).post("/auth/oauth/token").send({
      code,
      clientId: publicClient.clientId,
      redirectUri: REDIRECT_URI,
      codeVerifier: verifier,
    });
    expect(rightful.status).toBe(200);
  });
});
