import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import app from "../src/app";
import { db } from "../src/db";
import { auditLogs } from "../src/db/schema";
import { eq, and, desc } from "drizzle-orm";
import {
  createTestClient,
  refreshOperationId,
  registerTestUser,
  seedDefaultRole,
  uniqueIp,
  TestClient,
  TestUser,
} from "./helpers";

/** Newest audit rows for a client, optionally filtered by action */
async function rowsFor(clientUuid: string, action?: string) {
  return db
    .select()
    .from(auditLogs)
    .where(
      action
        ? and(eq(auditLogs.clientId, clientUuid), eq(auditLogs.action, action))
        : eq(auditLogs.clientId, clientUuid)
    )
    .orderBy(desc(auditLogs.createdAt));
}

describe("audit write path", () => {
  let client: TestClient;
  let admin: TestUser;

  beforeAll(async () => {
    client = await createTestClient("audit-app");
    await seedDefaultRole(client.id, [
      { resource: "roles", action: "write" },
      { resource: "api-keys", action: "write" },
      { resource: "users", action: "write" },
    ]);
    admin = await registerTestUser(client, "audit-admin@example.com");
  });

  const auth = (token: string) => ({ Authorization: `Bearer ${token}` });

  it("records client.created for the operator", async () => {
    const rows = await rowsFor(client.id, "client.created");
    expect(rows.length).toBe(1);
    expect(rows[0].actorType).toBe("operator");
    expect(rows[0].targetId).toBe(client.id);
    expect(rows[0].details).toMatchObject({ name: "audit-app" });
  });

  it("records registration with the actor and method", async () => {
    const rows = await rowsFor(client.id, "user.registered");
    expect(rows.length).toBe(1);
    expect(rows[0].actorType).toBe("user");
    expect(rows[0].actorId).toBe(admin.id);
    expect(rows[0].details).toMatchObject({ method: "password" });
    expect(rows[0].ip).toBeTruthy();
  });

  it("records successful and failed logins distinctly", async () => {
    await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: admin.email,
        password: admin.password,
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });

    await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: admin.email,
        password: "definitely-wrong",
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });

    const ok = await rowsFor(client.id, "user.login");
    expect(ok.length).toBe(1);
    expect(ok[0].actorId).toBe(admin.id);

    const failed = await rowsFor(client.id, "user.login_failed");
    expect(failed.length).toBe(1);
    expect(failed[0].actorType).toBe("anonymous");
    expect(failed[0].actorId).toBeNull();
    expect(failed[0].details).toMatchObject({ email: admin.email });
  });

  it("records replay detection as a security event", async () => {
    const user = await registerTestUser(client, "audit-replay@example.com");

    const refresh = (token: string) =>
      request(app).post("/auth/refresh").send({
        refreshToken: token,
        clientId: client.clientId,
        clientSecret: client.clientSecret,
        operationId: refreshOperationId(),
      });

    await refresh(user.refreshToken); // rotates
    await refresh(user.refreshToken); // replay of the revoked token

    const rows = await rowsFor(client.id, "session.replay_detected");
    expect(rows.length).toBe(1);
    expect(rows[0].actorId).toBe(user.id);
  });

  it("records management events with actor and target", async () => {
    // role.created
    const role = await request(app)
      .post("/roles")
      .set(auth(admin.accessToken))
      .send({ name: "audit-role" });
    expect(role.status).toBe(201);

    const roleRows = await rowsFor(client.id, "role.created");
    expect(roleRows.length).toBe(1);
    expect(roleRows[0].actorId).toBe(admin.id);
    expect(roleRows[0].targetType).toBe("role");
    expect(roleRows[0].targetId).toBe(role.body.id);

    // role.assigned targets the affected user, not the actor
    const member = await registerTestUser(client, "audit-member@example.com");
    await request(app)
      .post("/roles/assign")
      .set(auth(admin.accessToken))
      .send({ userId: member.id, roleId: role.body.id });

    const assignRows = await rowsFor(client.id, "role.assigned");
    expect(assignRows.length).toBe(1);
    expect(assignRows[0].actorId).toBe(admin.id);
    expect(assignRows[0].targetId).toBe(member.id);
    expect(assignRows[0].details).toMatchObject({ roleName: "audit-role" });

    // apikey.created never carries key material
    const key = await request(app)
      .post("/api-keys")
      .set(auth(admin.accessToken))
      .send({ name: "audit-key", scopes: ["users:read"] });
    expect(key.status).toBe(201);

    const keyRows = await rowsFor(client.id, "apikey.created");
    expect(keyRows.length).toBe(1);
    expect(JSON.stringify(keyRows[0].details)).not.toContain(key.body.key);

    // user.deactivated
    await request(app)
      .patch(`/users/${member.id}`)
      .set(auth(admin.accessToken))
      .send({ isActive: false });

    const deact = await rowsFor(client.id, "user.deactivated");
    expect(deact.length).toBe(1);
    expect(deact[0].targetId).toBe(member.id);
  });

  it("scopes rows to the acting client", async () => {
    const other = await createTestClient("audit-other-app");
    await registerTestUser(other, "audit-other@example.com");

    const otherRows = await rowsFor(other.id);
    const actions = otherRows.map((r) => r.action);
    expect(actions).toContain("user.registered");

    // Nothing from the other client's activity leaked into ours
    const ours = await rowsFor(client.id);
    expect(ours.every((r) => r.clientId === client.id)).toBe(true);
  });
});

describe("GET /audit read API", () => {
  let client: TestClient;
  let reader: TestUser;

  beforeAll(async () => {
    client = await createTestClient("audit-read-app");
    await seedDefaultRole(client.id, [
      { resource: "audit", action: "read" },
      { resource: "roles", action: "write" },
    ]);
    reader = await registerTestUser(client, "audit-reader@example.com");
  });

  const auth = (token: string) => ({ Authorization: `Bearer ${token}` });

  it("requires the dedicated audit:read permission", async () => {
    const other = await createTestClient("audit-noperm-app");
    await seedDefaultRole(other.id, [
      { resource: "users", action: "read" },
    ], "audit-noperm-default");
    const peon = await registerTestUser(other, "audit-peon@example.com");

    const res = await request(app).get("/audit").set(auth(peon.accessToken));
    expect(res.status).toBe(403);
    expect(res.body.code).toBe("INSUFFICIENT_PERMISSIONS");
  });

  it("lists the client's history newest first with filters", async () => {
    // Generate one more event after registration
    await request(app)
      .post("/roles")
      .set(auth(reader.accessToken))
      .send({ name: "read-api-role" });

    const all = await request(app).get("/audit").set(auth(reader.accessToken));
    expect(all.status).toBe(200);
    const actions = all.body.entries.map((e: { action: string }) => e.action);
    expect(actions).toContain("client.created");
    expect(actions).toContain("user.registered");
    expect(actions).toContain("role.created");

    // Newest first
    const times = all.body.entries.map((e: { createdAt: string }) =>
      new Date(e.createdAt).getTime()
    );
    expect([...times].sort((a, b) => b - a)).toEqual(times);

    // Every row belongs to this client
    expect(
      all.body.entries.every(
        (e: { clientId: string }) => e.clientId === client.id
      )
    ).toBe(true);

    // Action filter
    const filtered = await request(app)
      .get("/audit?action=role.created")
      .set(auth(reader.accessToken));
    expect(filtered.body.entries.length).toBe(1);
    expect(filtered.body.entries[0].details).toMatchObject({
      name: "read-api-role",
    });
  });

  it("pages with the before cursor", async () => {
    const page1 = await request(app)
      .get("/audit?limit=2")
      .set(auth(reader.accessToken));
    expect(page1.body.entries.length).toBe(2);
    expect(page1.body.nextBefore).toBeTruthy();

    const page2 = await request(app)
      .get(`/audit?limit=2&before=${encodeURIComponent(page1.body.nextBefore)}`)
      .set(auth(reader.accessToken));

    const ids1 = page1.body.entries.map((e: { id: string }) => e.id);
    const ids2 = page2.body.entries.map((e: { id: string }) => e.id);
    for (const id of ids2) expect(ids1).not.toContain(id);
  });
});
