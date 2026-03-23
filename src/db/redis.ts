import Redis from "ioredis";
import { env } from "../utils/env";

export const redis = new Redis(env.REDIS_URL, {
  maxRetriesPerRequest: 3,
  lazyConnect: true,
});

redis.on("error", (err) => console.error("Redis error:", err));
