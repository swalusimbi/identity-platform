import { describe, it, expect } from "vitest";
import request from "supertest";
import app from "../src/app";

// The suite runs with NODE_ENV=development and no CORS_ORIGINS
describe("CORS in development", () => {
  const preflight = (origin: string) =>
    request(app)
      .options("/auth/login")
      .set("Origin", origin)
      .set("Access-Control-Request-Method", "POST");

  it("allows localhost frontends on any port", async () => {
    for (const origin of [
      "http://localhost:5173",
      "http://127.0.0.1:3000",
      "http://[::1]:8080",
      "http://localhost",
    ]) {
      const res = await preflight(origin);
      expect(res.headers["access-control-allow-origin"]).toBe(origin);
      expect(res.headers["access-control-allow-credentials"]).toBe("true");
    }
  });

  it("refuses other origins", async () => {
    for (const origin of [
      "https://evil.example.com",
      "http://localhost.evil.example.com",
      "http://192.168.1.20:5173",
    ]) {
      const res = await preflight(origin);
      expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    }
  });
});
