import { describe, it, expect } from "vitest";
import request from "supertest";
import app from "../src/app";

describe("rate limiting", () => {
  it("limits login attempts per IP and sets headers", async () => {
    const ip = "10.99.99.1"; // Dedicated IP, never reused by helpers

    const attempt = () =>
      request(app).post("/auth/login").set("X-Forwarded-For", ip).send({
        email: "limited@example.com",
        password: "wrong-password",
        clientId: "cl_bogus",
        clientSecret: "cs_bogus",
      });

    for (let i = 0; i < 5; i++) {
      const res = await attempt();
      expect(res.status).toBe(401); // Invalid client, but allowed through
      expect(res.headers["x-ratelimit-limit"]).toBe("5");
    }

    const blocked = await attempt();
    expect(blocked.status).toBe(429);
    expect(blocked.headers["x-ratelimit-remaining"]).toBe("0");
  });

  it("does not throttle other IPs", async () => {
    const res = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", "10.99.99.2")
      .send({
        email: "limited@example.com",
        password: "wrong-password",
        clientId: "cl_bogus",
        clientSecret: "cs_bogus",
      });
    expect(res.status).toBe(401);
  });
});
