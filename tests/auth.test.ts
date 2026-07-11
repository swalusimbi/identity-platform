import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import app from "../src/app";
import { db } from "../src/db";
import { refreshTokens } from "../src/db/schema";
import { eq } from "drizzle-orm";
import { hashToken } from "../src/services/token";
import {
  createTestClient,
  registerTestUser,
  refreshOperationId,
  uniqueIp,
  TestClient,
} from "./helpers";

describe("health", () => {
  it("reports ok when redis and the database are up", async () => {
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      status: "ok",
      redis: "ok",
      database: "ok",
    });
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

  function refresh(
    refreshToken: string,
    c: TestClient = client,
    operationId = refreshOperationId()
  ) {
    return request(app).post("/auth/refresh").send({
      refreshToken,
      clientId: c.clientId,
      clientSecret: c.clientSecret,
      operationId,
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

  it("does not consume a token when the operation id is missing", async () => {
    const user = await registerTestUser(client, "missing-operation@example.com");

    const missing = await request(app).post("/auth/refresh").send({
      refreshToken: user.refreshToken,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
    });
    expect(missing.status).toBe(400);

    const valid = await refresh(user.refreshToken);
    expect(valid.status).toBe(200);
  });

  it("replaces an unused successor when a response-loss retry matches", async () => {
    const user = await registerTestUser(client, "refresh-retry@example.com");
    const operationId = refreshOperationId();

    const first = await refresh(user.refreshToken, client, operationId);
    expect(first.status).toBe(200);

    const [predecessor] = await db
      .select({ operationHash: refreshTokens.rotationOperationHash })
      .from(refreshTokens)
      .where(eq(refreshTokens.tokenHash, hashToken(user.refreshToken)));
    expect(predecessor.operationHash).toBe(hashToken(operationId));
    expect(predecessor.operationHash).not.toBe(operationId);

    const retry = await refresh(user.refreshToken, client, operationId);
    expect(retry.status).toBe(200);
    expect(retry.body.refreshToken).not.toBe(first.body.refreshToken);

    const replaced = await refresh(first.body.refreshToken);
    expect(replaced.status).toBe(401);

    const current = await refresh(retry.body.refreshToken);
    expect(current.status).toBe(200);
  });

  it("treats a matching retry as replay after the successor was used", async () => {
    const user = await registerTestUser(client, "refresh-used-successor@example.com");
    const operationId = refreshOperationId();

    const first = await refresh(user.refreshToken, client, operationId);
    expect(first.status).toBe(200);
    const second = await refresh(first.body.refreshToken);
    expect(second.status).toBe(200);

    const replay = await refresh(user.refreshToken, client, operationId);
    expect(replay.status).toBe(401);
    expect((await refresh(second.body.refreshToken)).status).toBe(401);
  });

  it("treats a matching retry outside the grace period as replay", async () => {
    const user = await registerTestUser(client, "refresh-expired-grace@example.com");
    const operationId = refreshOperationId();

    const first = await refresh(user.refreshToken, client, operationId);
    expect(first.status).toBe(200);
    await db
      .update(refreshTokens)
      .set({ rotatedAt: new Date(0) })
      .where(eq(refreshTokens.tokenHash, hashToken(user.refreshToken)));

    const replay = await refresh(user.refreshToken, client, operationId);
    expect(replay.status).toBe(401);
    expect((await refresh(first.body.refreshToken)).status).toBe(401);
  });

  it("allows only one concurrent rotation of the same token", async () => {
    const user = await registerTestUser(client, "concurrent-refresh@example.com");

    const [first, second] = await Promise.all([
      refresh(user.refreshToken),
      refresh(user.refreshToken),
    ]);

    expect([first.status, second.status].sort()).toEqual([200, 401]);

    const rows = await db
      .select({ id: refreshTokens.id })
      .from(refreshTokens)
      .where(eq(refreshTokens.userId, user.id));
    expect(rows).toHaveLength(2);
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

  it("does not revoke a family when a rotated token is replayed through another client", async () => {
    const user = await registerTestUser(client, "foreign-replay@example.com");
    const first = await refresh(user.refreshToken);
    expect(first.status).toBe(200);

    const publicClient = await createTestClient("refresh-public-replay-app", {
      isPublic: true,
    });
    const foreignReplay = await refresh(user.refreshToken, publicClient);
    expect(foreignReplay.status).toBe(401);

    const stillAlive = await refresh(first.body.refreshToken);
    expect(stillAlive.status).toBe(200);
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
  it("does not treat a logged out token as replay", async () => {
    const client = await createTestClient("logout-retry-app");
    const user = await registerTestUser(client, "logout-retry@example.com");

    // A second session that must survive the retry below
    const second = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: user.email,
        password: user.password,
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });
    expect(second.status).toBe(200);

    await request(app).post("/auth/logout").send({
      refreshToken: user.refreshToken,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
    });

    // The logged out device retries: plain 401, no family revocation
    const retry = await request(app).post("/auth/refresh").send({
      refreshToken: user.refreshToken,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      operationId: refreshOperationId(),
    });
    expect(retry.status).toBe(401);

    const alive = await request(app).post("/auth/refresh").send({
      refreshToken: second.body.refreshToken,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      operationId: refreshOperationId(),
    });
    expect(alive.status).toBe(200);
  });

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
      operationId: refreshOperationId(),
    });
    expect(after.status).toBe(401);
  });
});
