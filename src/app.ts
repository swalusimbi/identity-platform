import express from "express";
import cors from "cors";
import helmet from "helmet";
import { env } from "./utils/env";
import { errorHandler } from "./utils/errors";
import { redis } from "./db/redis";
import { sql } from "./db";

// Routes
import authRoutes from "./routes/auth";
import verifyRoutes from "./routes/verify";
import rolesRoutes from "./routes/roles";
import apiKeysRoutes from "./routes/apiKeys";
import clientsRoutes from "./routes/clients";
import oauthRoutes from "./routes/oauth";
import jwksRoutes from "./routes/jwks";

const app = express();

// ─── Global middleware ────────────────────────────────────────────

/**
 * Parse CORS_ORIGINS into the shape the cors package expects.
 * "*.example.com" becomes a subdomain regex, anything else is exact.
 */
function corsOrigins(value: string): (string | RegExp)[] {
  return value.split(",").map((entry) => {
    const origin = entry.trim();
    if (origin.startsWith("*.")) {
      const domain = origin.slice(2).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      return new RegExp(`\\.${domain}$`);
    }
    return origin;
  });
}

// Outside production all origins are allowed. In production only the
// configured origins are, or none when CORS_ORIGINS is unset.
const allowedOrigins =
  env.NODE_ENV !== "production"
    ? true
    : env.CORS_ORIGINS
      ? corsOrigins(env.CORS_ORIGINS)
      : false;

app.use(helmet());
app.use(cors({ origin: allowedOrigins, credentials: true }));
app.use(express.json({ limit: "16kb" }));

// Trust proxy (behind Nginx)
app.set("trust proxy", 1);

// ─── Health check ─────────────────────────────────────────────────

app.get("/health", async (_req, res) => {
  const checks: Record<string, string> = { status: "ok" };

  try {
    await redis.ping();
    checks.redis = "ok";
  } catch {
    checks.redis = "down";
  }

  try {
    await sql`select 1`;
    checks.database = "ok";
  } catch {
    checks.database = "down";
  }

  const allOk = Object.values(checks).every((v) => v === "ok");
  res.status(allOk ? 200 : 503).json(checks);
});

// ─── Routes ───────────────────────────────────────────────────────

app.use("/auth", authRoutes);
app.use("/auth/oauth", oauthRoutes);
app.use("/auth/verify", verifyRoutes);
app.use("/roles", rolesRoutes);
app.use("/api-keys", apiKeysRoutes);
app.use("/clients", clientsRoutes);
app.use(jwksRoutes);

// ─── Error handler (must be last) ─────────────────────────────────

app.use(errorHandler);

export default app;
