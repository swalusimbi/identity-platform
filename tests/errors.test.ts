import { describe, it, expect, vi, afterEach } from "vitest";
import request from "supertest";
import type { Request, Response } from "express";
import app from "../src/app";
import { errorHandler } from "../src/utils/errors";
import { createTestClient, registerTestUser, uniqueIp } from "./helpers";

describe("request body errors", () => {
  const post = () =>
    request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", uniqueIp())
      .set("Content-Type", "application/json");

  afterEach(() => vi.restoreAllMocks());

  it("answers malformed JSON with 400 INVALID_JSON", async () => {
    const res = await post().send("{nope");

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: "Request body is not valid JSON", code: "INVALID_JSON" });
  });

  it("answers a body over the 16 KB cap with 413 PAYLOAD_TOO_LARGE", async () => {
    const res = await post().send(JSON.stringify({ email: "a".repeat(20_000) }));

    expect(res.status).toBe(413);
    expect(res.body.code).toBe("PAYLOAD_TOO_LARGE");
  });

  it("answers an unsupported content encoding with 415", async () => {
    const res = await post().set("Content-Encoding", "compress").send("{}");

    expect(res.status).toBe(415);
    expect(res.body.code).toBe("UNSUPPORTED_ENCODING");
  });

  it("answers a body that is not the gzip it claims with 400", async () => {
    const res = await post().set("Content-Encoding", "gzip").send("{}");

    expect(res.status).toBe(400);
    expect(res.body.code).toBe("BAD_REQUEST");
  });

  it("does not log client body errors as unhandled", async () => {
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});

    await post().send("{nope");

    expect(logged).not.toHaveBeenCalled();
  });
});

describe("error codes on authentication failures", () => {
  it("names a missing or unusable authorization header", async () => {
    const missing = await request(app).get("/sessions");
    expect(missing.status).toBe(401);
    expect(missing.body.code).toBe("UNAUTHENTICATED");

    const scheme = await request(app).get("/sessions").set("Authorization", "Basic abc");
    expect(scheme.status).toBe(401);
    expect(scheme.body.code).toBe("INVALID_AUTHORIZATION");
  });

  it("names an unknown API key", async () => {
    const res = await request(app).get("/roles").set("Authorization", "ApiKey sk_not_a_real_key");

    expect(res.status).toBe(401);
    expect(res.body.code).toBe("INVALID_API_KEY");
  });

  it("names a wrong admin key", async () => {
    const res = await request(app)
      .get("/clients")
      .set("X-Forwarded-For", uniqueIp())
      .set("X-Admin-Key", "wrong");

    expect(res.status).toBe(403);
    expect(res.body.code).toBe("INVALID_ADMIN_KEY");
  });
});

describe("errors outside any route", () => {
  afterEach(() => vi.restoreAllMocks());

  it("answers an unknown route with JSON 404 ROUTE_NOT_FOUND", async () => {
    for (const res of [
      await request(app).get("/nope"),
      await request(app).post("/auth/nope").send({}),
      await request(app).get("/admin/missing.js"),
    ]) {
      expect(res.status).toBe(404);
      expect(res.type).toBe("application/json");
      expect(res.body).toEqual({ error: "Route not found", code: "ROUTE_NOT_FOUND" });
    }
  });

  it("answers an unexpected error with 500 INTERNAL_ERROR and no detail", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };

    errorHandler(new Error("connection string leaked"), {} as Request, res as unknown as Response, () => {});

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({ error: "Internal server error", code: "INTERNAL_ERROR" });
  });
});

describe("access token failures", () => {
  afterEach(() => vi.useRealTimers());

  const sessions = (token: string) =>
    request(app).get("/sessions").set("Authorization", `Bearer ${token}`);

  it("tells an expired token from an invalid one", async () => {
    const client = await createTestClient("token-codes-app");
    const user = await registerTestUser(client, "token-codes@example.com");

    const [header, payload, signature] = user.accessToken.split(".");
    const tampered = `${header}.${payload}.${signature.startsWith("A") ? "B" : "A"}${signature.slice(1)}`;
    const invalid = await sessions(tampered);
    expect(invalid.status).toBe(401);
    expect(invalid.body.code).toBe("TOKEN_INVALID");

    const garbage = await sessions("not-a-jwt");
    expect(garbage.body.code).toBe("TOKEN_INVALID");

    // Only the clock moves, past the 15 minute access token lifetime
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 16 * 60 * 1000);
    const expired = await sessions(user.accessToken);
    expect(expired.status).toBe(401);
    expect(expired.body).toEqual({ error: "Token expired", code: "TOKEN_EXPIRED" });
  });
});
