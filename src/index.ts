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

  const onListening = () => {
    console.log(`✓ Identity Platform listening on ${env.BIND_HOST ?? "all interfaces"}, port ${env.PORT}`);
    console.log(`  Environment: ${env.NODE_ENV}`);
    console.log(`  URL: ${env.SERVICE_URL}`);
  };

  if (env.BIND_HOST) {
    app.listen(env.PORT, env.BIND_HOST, onListening);
  } else {
    app.listen(env.PORT, onListening);
  }
}

start().catch(console.error);
