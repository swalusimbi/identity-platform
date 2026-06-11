import app from "./app";
import { env } from "./utils/env";
import { redis } from "./db/redis";

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
