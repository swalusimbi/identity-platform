import { describe, it, expect } from "vitest";
import request from "supertest";
import app from "../src/app";

describe("rate limiting", () => {
  const attempt = (ip: string, email: string, clientId = "cl_bogus") =>
    request(app).post("/auth/login").set("X-Forwarded-For", ip).send({
      email,
      password: "wrong-password",
      clientId,
      clientSecret: "cs_bogus",
    });

  it("limits login attempts per IP and account and sets headers", async () => {
    const ip = "10.99.99.1"; // Dedicated IP, never reused by helpers

    for (let i = 0; i < 5; i++) {
      const res = await attempt(ip, "limited@example.com");
      expect(res.status).toBe(401); // Invalid client, but allowed through
      expect(res.headers["x-ratelimit-limit"]).toBe("5");
    }

    const blocked = await attempt(ip, "limited@example.com");
    expect(blocked.status).toBe(429);
    expect(blocked.headers["x-ratelimit-remaining"]).toBe("0");
  });

  it("gives each account behind one NAT its own allowance", async () => {
    const ip = "10.99.99.3"; // One building, many staff

    // Two users each burn their 5 attempts, neither blocks the other
    for (let i = 0; i < 5; i++) {
      expect((await attempt(ip, "nurse-a@example.com")).status).toBe(401);
      expect((await attempt(ip, "nurse-b@example.com")).status).toBe(401);
    }
    expect((await attempt(ip, "nurse-a@example.com")).status).toBe(429);

    // A third user on the same IP is still fine
    expect((await attempt(ip, "nurse-c@example.com")).status).toBe(401);
  });

  it("caps total attempts per IP across many emails", async () => {
    const ip = "10.99.99.4";

    // Spray 30 different emails from one IP, the coarse cap kicks in
    for (let i = 0; i < 30; i++) {
      const res = await attempt(ip, `spray-${i}@example.com`);
      expect(res.status).toBe(401);
    }

    const blocked = await attempt(ip, "spray-fresh@example.com");
    expect(blocked.status).toBe(429);
  });

  it("does not throttle other IPs", async () => {
    const res = await attempt("10.99.99.2", "limited@example.com");
    expect(res.status).toBe(401);
  });

  it("gives the same email under two clients independent allowances", async () => {
    const ip = "10.99.99.5";

    // The same address is two unrelated accounts across clients, so
    // exhausting it on one client must not lock it on another
    for (let i = 0; i < 5; i++) {
      expect((await attempt(ip, "shared@example.com", "cl_app_one")).status).toBe(401);
    }
    expect((await attempt(ip, "shared@example.com", "cl_app_one")).status).toBe(429);

    expect((await attempt(ip, "shared@example.com", "cl_app_two")).status).toBe(401);
  });
});
