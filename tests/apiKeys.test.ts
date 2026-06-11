import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import app from "../src/app";
import {
  createTestClient,
  registerTestUser,
  seedDefaultRole,
  TestClient,
  TestUser,
} from "./helpers";

describe("API keys", () => {
  let client: TestClient;
  let admin: TestUser;

  beforeAll(async () => {
    client = await createTestClient("apikeys-app");
    await seedDefaultRole(client.id, [
      { resource: "api-keys", action: "read" },
      { resource: "api-keys", action: "write" },
    ]);
    admin = await registerTestUser(client, "apikeys-admin@example.com");
  });

  const auth = (token: string) => ({ Authorization: `Bearer ${token}` });

  it("creates a key, shows it once and lists only the prefix", async () => {
    const res = await request(app)
      .post("/api-keys")
      .set(auth(admin.accessToken))
      .send({ name: "ci-key", scopes: ["deploys:write"] });

    expect(res.status).toBe(201);
    expect(res.body.key).toMatch(/^sk_/);
    expect(res.body.keyPrefix).toMatch(/^sk_/);
    expect(res.body.key.startsWith(res.body.keyPrefix)).toBe(true);

    const list = await request(app)
      .get("/api-keys")
      .set(auth(admin.accessToken));
    expect(list.status).toBe(200);
    const listed = list.body.find((k: { id: string }) => k.id === res.body.id);
    expect(listed).toBeTruthy();
    expect(listed.key).toBeUndefined();
    expect(listed.keyHash).toBeUndefined();
  });

  it("verifies an API key and enforces scopes", async () => {
    const created = await request(app)
      .post("/api-keys")
      .set(auth(admin.accessToken))
      .send({ name: "scoped-key", scopes: ["meters:read"] });
    const key = created.body.key;

    const ok = await request(app)
      .post("/auth/verify")
      .send({ apiKey: key, requiredPermission: "meters:read" });
    expect(ok.body).toMatchObject({ valid: true, authorized: true });
    expect(ok.body.apiKey.scopes).toEqual(["meters:read"]);

    const denied = await request(app)
      .post("/auth/verify")
      .send({ apiKey: key, requiredPermission: "meters:write" });
    expect(denied.body.valid).toBe(true);
    expect(denied.body.authorized).toBe(false);
  });

  it("supports wildcard scopes", async () => {
    const created = await request(app)
      .post("/api-keys")
      .set(auth(admin.accessToken))
      .send({ name: "wildcard-key", scopes: ["meters:*"] });

    const ok = await request(app)
      .post("/auth/verify")
      .send({ apiKey: created.body.key, requiredPermission: "meters:write" });
    expect(ok.body).toMatchObject({ valid: true, authorized: true });
  });

  it("rejects a revoked key", async () => {
    const created = await request(app)
      .post("/api-keys")
      .set(auth(admin.accessToken))
      .send({ name: "doomed-key" });

    const del = await request(app)
      .delete(`/api-keys/${created.body.id}`)
      .set(auth(admin.accessToken));
    expect(del.status).toBe(200);

    const verify = await request(app)
      .post("/auth/verify")
      .send({ apiKey: created.body.key });
    expect(verify.body.valid).toBe(false);
  });

  it("serves client scoped routes to ApiKey principals", async () => {
    const created = await request(app)
      .post("/api-keys")
      .set(auth(admin.accessToken))
      .send({ name: "roles-reader-key", scopes: ["roles:read"] });

    // Used to crash with a 500 because handlers read req.user!.cid
    const res = await request(app)
      .get("/roles")
      .set("Authorization", `ApiKey ${created.body.key}`);
    expect(res.status).toBe(200);
    expect(res.body.map((r: { name: string }) => r.name)).toContain("default");
  });

  it("authenticates requests with the ApiKey scheme", async () => {
    const created = await request(app)
      .post("/api-keys")
      .set(auth(admin.accessToken))
      .send({ name: "auth-scheme-key", scopes: ["api-keys:read"] });

    // /api-keys list uses req.user (JWT) internally, so exercise the
    // middleware through a key lacking the scope instead
    const denied = await request(app)
      .post("/api-keys")
      .set("Authorization", `ApiKey ${created.body.key}`)
      .send({ name: "should-fail" });
    expect(denied.status).toBe(403);
    expect(denied.body.code).toBe("INSUFFICIENT_SCOPE");
  });

  it("blocks users without api-keys:write from creating keys", async () => {
    const other = await createTestClient("apikeys-unpriv-app");
    const peon = await registerTestUser(other, "apikeys-peon@example.com");

    const res = await request(app)
      .post("/api-keys")
      .set(auth(peon.accessToken))
      .send({ name: "sneaky-key" });
    expect(res.status).toBe(403);
  });
});
