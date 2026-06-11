import { describe, it, expect } from "vitest";
import request from "supertest";
import app from "../src/app";

const ADMIN_KEY = process.env.ADMIN_KEY!;

describe("client registration (admin)", () => {
  it("rejects requests without the admin key", async () => {
    const res = await request(app).post("/clients").send({ name: "nope" });
    expect(res.status).toBe(403);
  });

  it("rejects a wrong admin key", async () => {
    const res = await request(app)
      .post("/clients")
      .set("X-Admin-Key", "wrong-key")
      .send({ name: "nope" });
    expect(res.status).toBe(403);
  });

  it("creates a client and returns the secret exactly once", async () => {
    const res = await request(app)
      .post("/clients")
      .set("X-Admin-Key", ADMIN_KEY)
      .send({ name: "client-test-app", redirectUris: ["https://app.example.com/cb"] });

    expect(res.status).toBe(201);
    expect(res.body.clientId).toMatch(/^cl_/);
    expect(res.body.clientSecret).toMatch(/^cs_/);
    expect(res.body.warning).toBeTruthy();

    // Listing never exposes the secret
    const list = await request(app).get("/clients").set("X-Admin-Key", ADMIN_KEY);
    expect(list.status).toBe(200);
    const created = list.body.find(
      (c: { clientId: string }) => c.clientId === res.body.clientId
    );
    expect(created).toBeTruthy();
    expect(created.clientSecret).toBeUndefined();
    expect(created.clientSecretHash).toBeUndefined();
  });
});
