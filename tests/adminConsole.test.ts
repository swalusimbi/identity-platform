import { describe, expect, it } from "vitest";
import request from "supertest";
import app from "../src/app";

describe("admin console", () => {
  it("serves the console shell", async () => {
    const res = await request(app).get("/admin");

    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toContain("text/html");
    expect(res.text).toContain("Identity Admin");
    expect(res.text).toContain("/admin/app.js");
  });

  it("serves console assets", async () => {
    const script = await request(app).get("/admin/app.js");
    expect(script.status).toBe(200);
    expect(script.headers["content-type"]).toContain("javascript");
    expect(script.text).toContain("identityAdminSettings");
    expect(script.text).toContain("sessionStorage.setItem(settingsKey");
    expect(script.text).toContain("localStorage.removeItem(settingsKey)");
    expect(script.text).not.toContain("localStorage.setItem(");

    const css = await request(app).get("/admin/styles.css");
    expect(css.status).toBe(200);
    expect(css.headers["content-type"]).toContain("text/css");
    expect(css.text).toContain(".shell");
  });

  it("offers an explicit credential clear action", async () => {
    const res = await request(app).get("/admin");

    expect(res.status).toBe(200);
    expect(res.text).toContain('id="clearCredentials"');
  });
});
