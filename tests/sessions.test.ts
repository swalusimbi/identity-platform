import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import app from "../src/app";
import {
  createTestClient,
  refreshOperationId,
  registerTestUser,
  seedDefaultRole,
  uniqueIp,
  TestClient,
  TestUser,
} from "./helpers";

describe("sessions API", () => {
  let client: TestClient;

  beforeAll(async () => {
    client = await createTestClient("sessions-app");
    await seedDefaultRole(client.id, [
      { resource: "api-keys", action: "write" },
    ]);
  });

  const auth = (token: string) => ({ Authorization: `Bearer ${token}` });

  const login = (user: TestUser, ip = uniqueIp()) =>
    request(app).post("/auth/login").set("X-Forwarded-For", ip).send({
      email: user.email,
      password: user.password,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
    });

  const refresh = (token: string) =>
    request(app).post("/auth/refresh").send({
      refreshToken: token,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      operationId: refreshOperationId(),
    });

  it("requires authentication", async () => {
    const res = await request(app).get("/sessions");
    expect(res.status).toBe(401);
  });

  it("refuses API key principals", async () => {
    const admin = await registerTestUser(client, "sessions-admin@example.com");
    const key = await request(app)
      .post("/api-keys")
      .set(auth(admin.accessToken))
      .send({ name: "sessions-key", scopes: ["*"] });

    const res = await request(app)
      .get("/sessions")
      .set("Authorization", `ApiKey ${key.body.key}`);
    expect(res.status).toBe(403);
    expect(res.body.code).toBe("BEARER_REQUIRED");
  });

  it("lists active sessions with metadata and without token material", async () => {
    const user = await registerTestUser(client, "sessions-list@example.com");
    const deviceIp = uniqueIp();
    await login(user, deviceIp); // a second device

    const res = await request(app)
      .get("/sessions")
      .set(auth(user.accessToken));

    expect(res.status).toBe(200);
    expect(res.body.length).toBe(2);
    const ips = res.body.map((s: { ip: string }) => s.ip);
    expect(ips).toContain(deviceIp);
    for (const session of res.body) {
      expect(session.id).toBeTruthy();
      expect(session.expiresAt).toBeTruthy();
      const raw = JSON.stringify(session);
      expect(raw).not.toContain(user.refreshToken);
      expect(raw).not.toMatch(/hash/i);
    }
  });

  it("revokes a single session and only that one", async () => {
    const user = await registerTestUser(client, "sessions-one@example.com");
    const second = await login(user);

    const list = await request(app)
      .get("/sessions")
      .set(auth(user.accessToken));
    expect(list.body.length).toBe(2);

    const del = await request(app)
      .delete(`/sessions/${list.body[0].id}`)
      .set(auth(user.accessToken));
    expect(del.status).toBe(200);

    const after = await request(app)
      .get("/sessions")
      .set(auth(user.accessToken));
    expect(after.body.length).toBe(1);
    expect(after.body[0].id).toBe(list.body[1].id);

    // The newest session (listed first) was the second login,
    // so its refresh token is dead and the original still works
    expect((await refresh(second.body.refreshToken)).status).toBe(401);
    expect((await refresh(user.refreshToken)).status).toBe(200);
  });

  it("does not reveal or touch another user's sessions", async () => {
    const alice = await registerTestUser(client, "sessions-alice@example.com");
    const bob = await registerTestUser(client, "sessions-bob@example.com");

    const bobSessions = await request(app)
      .get("/sessions")
      .set(auth(bob.accessToken));
    const bobSessionId = bobSessions.body[0].id;

    const res = await request(app)
      .delete(`/sessions/${bobSessionId}`)
      .set(auth(alice.accessToken));
    expect(res.status).toBe(404);

    // Bob is untouched
    expect((await refresh(bob.refreshToken)).status).toBe(200);
  });

  it("logs out everywhere", async () => {
    const user = await registerTestUser(client, "sessions-all@example.com");
    await login(user);
    await login(user);

    const res = await request(app)
      .delete("/sessions")
      .set(auth(user.accessToken));
    expect(res.status).toBe(200);
    expect(res.body.count).toBe(3);

    const after = await request(app)
      .get("/sessions")
      .set(auth(user.accessToken));
    expect(after.body.length).toBe(0);

    // Every refresh token is dead, including the caller's own
    expect((await refresh(user.refreshToken)).status).toBe(401);
  });
});
