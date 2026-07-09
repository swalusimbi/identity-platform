import app from "./app";
import { env } from "./utils/env";
import { redis } from "./db/redis";
import { scheduleRefreshTokenCleanup } from "./jobs/cleanup";

async function start() {
  try {
    await redis.connect();
    console.log("✓ Redis connected");
  } catch (err) {
    console.warn("⚠ Redis connection failed — rate limiting disabled:", err);
  }

  scheduleRefreshTokenCleanup();

  app.listen(env.PORT, () => {
    console.log(`✓ Identity Platform running on port ${env.PORT}`);
    console.log(`  Environment: ${env.NODE_ENV}`);
    console.log(`  URL: ${env.SERVICE_URL}`);
  });
}

start().catch(console.error);
