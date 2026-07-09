import { describe, it, expect } from "vitest";
import request from "supertest";
import app from "../src/app";

describe("live API docs", () => {
  it("serves the openapi spec", async () => {
    const res = await request(app).get("/openapi.json");

    expect(res.status).toBe(200);
    expect(res.type).toBe("application/json");
    expect(res.body.openapi).toMatch(/^3\.1/);
    expect(res.body.info.title).toBe("Identity Platform API");
    // Relative server first, so try it out targets the serving host
    expect(res.body.servers[0].url).toBe("/");
    expect(Object.keys(res.body.paths)).toContain("/auth/login");
  });

  it("serves the docs viewer without inline scripts", async () => {
    const res = await request(app).get("/docs");

    expect(res.status).toBe(200);
    expect(res.type).toBe("text/html");
    expect(res.text).toContain('id="swagger-ui"');
    // helmet's CSP is script-src 'self', so every script must be a file
    expect(res.text).not.toMatch(/<script>[^<]/);
  });

  it("serves the viewer assets and loader", async () => {
    const bundle = await request(app).get("/docs/swagger-ui-bundle.js");
    expect(bundle.status).toBe(200);

    const init = await request(app).get("/docs/init.js");
    expect(init.status).toBe(200);
    expect(init.text).toContain('url: "/openapi.json"');
  });
});
