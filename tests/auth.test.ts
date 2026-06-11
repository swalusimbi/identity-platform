import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import app from "../src/app";
import {
  createTestClient,
  registerTestUser,
  uniqueIp,
  TestClient,
} from "./helpers";

describe("health", () => {
  it("reports ok when redis is up", async () => {
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: "ok", redis: "ok" });
  });
});

describe("auth flows", () => {
  let client: TestClient;

  beforeAll(async () => {
    client = await createTestClient("auth-flow-app");
  });

  it("registers a user and returns a token pair", async () => {
    const res = await request(app)
      .post("/auth/register")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: "Alice@Example.com",
        password: "password-123",
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });

    expect(res.status).toBe(201);
    expect(res.body.user.email).toBe("alice@example.com"); // lowercased
    expect(res.body.accessToken).toBeTruthy();
    expect(res.body.refreshToken).toBeTruthy();
    expect(res.body.expiresIn).toBe(900); // 15m
  });

  it("rejects duplicate registration under the same client", async () => {
    const res = await request(app)
      .post("/auth/register")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: "alice@example.com",
        password: "password-456",
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });

    expect(res.status).toBe(409);
    expect(res.body.code).toBe("EMAIL_EXISTS");
  });

  it("allows the same email under a different client", async () => {
    const other = await createTestClient("auth-flow-other-app");
    const res = await request(app)
      .post("/auth/register")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: "alice@example.com",
        password: "password-789",
        clientId: other.clientId,
        clientSecret: other.clientSecret,
      });

    expect(res.status).toBe(201);
  });

  it("rejects register with invalid client credentials", async () => {
    const res = await request(app)
      .post("/auth/register")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: "bob@example.com",
        password: "password-123",
        clientId: client.clientId,
        clientSecret: "cs_wrong",
      });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe("INVALID_CLIENT");
  });

  it("logs in with correct credentials", async () => {
    const res = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: "alice@example.com",
        password: "password-123",
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });

    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeTruthy();
    expect(res.body.refreshToken).toBeTruthy();
  });

  it("rejects login with a wrong password", async () => {
    const res = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: "alice@example.com",
        password: "not-the-password",
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe("INVALID_CREDENTIALS");
  });

  it("rejects login for a nonexistent user with the same error", async () => {
    const res = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: "ghost@example.com",
        password: "whatever-123",
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe("INVALID_CREDENTIALS");
  });

  it("validates the request body", async () => {
    const res = await request(app)
      .post("/auth/register")
      .set("X-Forwarded-For", uniqueIp())
      .send({ email: "not-an-email", password: "short" });

    expect(res.status).toBe(400);
    expect(res.body.code).toBe("VALIDATION_ERROR");
  });
});

describe("refresh token rotation", () => {
  let client: TestClient;

  beforeAll(async () => {
    client = await createTestClient("refresh-app");
  });

  function refresh(refreshToken: string, c: TestClient = client) {
    return request(app).post("/auth/refresh").send({
      refreshToken,
      clientId: c.clientId,
      clientSecret: c.clientSecret,
    });
  }

  it("rotates the refresh token and revokes the old one", async () => {
    const user = await registerTestUser(client, "rotate@example.com");

    const first = await refresh(user.refreshToken);
    expect(first.status).toBe(200);
    expect(first.body.refreshToken).not.toBe(user.refreshToken);

    // Old token was rotated out
    const replay = await refresh(user.refreshToken);
    expect(replay.status).toBe(401);
    expect(replay.body.code).toBe("INVALID_REFRESH_TOKEN");
  });

  it("revokes the whole family when a rotated token is replayed", async () => {
    const user = await registerTestUser(client, "family@example.com");

    const first = await refresh(user.refreshToken);
    expect(first.status).toBe(200);

    // Replaying the original (revoked) token must nuke everything
    await refresh(user.refreshToken);

    const second = await refresh(first.body.refreshToken);
    expect(second.status).toBe(401);
  });

  it("rejects a refresh token presented by a different client", async () => {
    const user = await registerTestUser(client, "crossclient@example.com");
    const other = await createTestClient("refresh-other-app");

    const res = await refresh(user.refreshToken, other);
    expect(res.status).toBe(401);
    expect(res.body.code).toBe("INVALID_REFRESH_TOKEN");

    // And it was not consumed by the failed attempt
    const legit = await refresh(user.refreshToken);
    expect(legit.status).toBe(200);
  });

  it("rejects garbage refresh tokens", async () => {
    const res = await refresh("not-a-real-token");
    expect(res.status).toBe(401);
  });
});

describe("logout", () => {
  it("revokes the refresh token", async () => {
    const client = await createTestClient("logout-app");
    const user = await registerTestUser(client, "logout@example.com");

    const res = await request(app).post("/auth/logout").send({
      refreshToken: user.refreshToken,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
    });
    expect(res.status).toBe(200);

    const after = await request(app).post("/auth/refresh").send({
      refreshToken: user.refreshToken,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
    });
    expect(after.status).toBe(401);
  });
});
