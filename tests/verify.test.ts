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

describe("POST /auth/verify", () => {
  let client: TestClient;
  let user: TestUser;

  beforeAll(async () => {
    client = await createTestClient("verify-app");
    await seedDefaultRole(client.id, [
      { resource: "reports", action: "read" },
    ]);
    user = await registerTestUser(client, "verify@example.com");
  });

  it("verifies a valid access token", async () => {
    const res = await request(app)
      .post("/auth/verify")
      .send({ token: user.accessToken });

    expect(res.status).toBe(200);
    expect(res.body.valid).toBe(true);
    expect(res.body.authorized).toBe(true);
    expect(res.body.user).toMatchObject({
      id: user.id,
      email: "verify@example.com",
      permissions: ["reports:read"],
    });
  });

  it("rejects a garbage token without an exception", async () => {
    const res = await request(app)
      .post("/auth/verify")
      .send({ token: "eyJ.garbage.token" });

    expect(res.status).toBe(200);
    expect(res.body.valid).toBe(false);
  });

  it("reports authorized=true when the required permission is held", async () => {
    const res = await request(app)
      .post("/auth/verify")
      .send({ token: user.accessToken, requiredPermission: "reports:read" });

    expect(res.body).toMatchObject({ valid: true, authorized: true });
  });

  it("reports authorized=false when the permission is missing", async () => {
    const res = await request(app)
      .post("/auth/verify")
      .send({ token: user.accessToken, requiredPermission: "reports:write" });

    expect(res.body.valid).toBe(true);
    expect(res.body.authorized).toBe(false);
  });

  it("requires either token or apiKey", async () => {
    const res = await request(app).post("/auth/verify").send({});
    expect(res.status).toBe(400);
  });
});
