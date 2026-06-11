import { describe, it, expect, beforeAll, vi } from "vitest";
import request from "supertest";
import app from "../src/app";
import {
  encryptState,
  decryptState,
  generateAuthCode,
  storeAuthCode,
  consumeAuthCode,
} from "../src/services/oauth";
import {
  createTestClient,
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
  });
});
