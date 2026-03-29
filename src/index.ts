import express from "express";
import cors from "cors";
import helmet from "helmet";
import { env } from "./utils/env";
import { errorHandler } from "./utils/errors";
import { redis } from "./db/redis";

// Routes
import authRoutes from "./routes/auth";
import verifyRoutes from "./routes/verify";
import rolesRoutes from "./routes/roles";
import apiKeysRoutes from "./routes/apiKeys";
import clientsRoutes from "./routes/clients";
import oauthRoutes from "./routes/oauth";

const app = express();

// ─── Global middleware ────────────────────────────────────────────

app.use(helmet());
app.use(
  cors({
    origin: env.NODE_ENV === "production"
      ? [
          "https://app.example.com",
          "https://tools.example.com",
          "https://img.example.com",
          /\.example\.com$/,
        ]
      : true,
    credentials: true,
  })
);
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

  // DB check happens implicitly via any route — keep health fast
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

// ─── Error handler (must be last) ─────────────────────────────────

app.use(errorHandler);

// ─── Start ────────────────────────────────────────────────────────

async function start() {
  try {
    await redis.connect();
    console.log("✓ Redis connected");
  } catch (err) {
    console.warn("⚠ Redis connection failed — rate limiting disabled:", err);
  }

  app.listen(env.PORT, () => {
    console.log(`✓ Auth service running on port ${env.PORT}`);
    console.log(`  Environment: ${env.NODE_ENV}`);
    console.log(`  URL: ${env.SERVICE_URL}`);
  });
}

start().catch(console.error);
