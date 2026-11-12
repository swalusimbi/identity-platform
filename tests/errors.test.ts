import { describe, it, expect, vi, afterEach } from "vitest";
import request from "supertest";
import app from "../src/app";
import { uniqueIp } from "./helpers";

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
