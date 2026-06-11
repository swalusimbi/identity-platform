import { Request, Response, NextFunction } from "express";
import { redis } from "../db/redis";
import { AppError } from "../utils/errors";

interface RateLimitConfig {
  windowMs: number; // Time window in milliseconds
  max: number; // Max requests per window
  keyPrefix?: string; // Redis key prefix
  keyGenerator?: (req: Request) => string; // Custom key extraction
}

/**
 * Redis-backed fixed window rate limiter
 *
 * Usage:
 *   router.post("/login", rateLimit({ windowMs: 60000, max: 5 }), loginHandler)
 *   router.post("/register", rateLimit({ windowMs: 3600000, max: 10, keyPrefix: "reg" }), registerHandler)
 */
export function rateLimit(config: RateLimitConfig) {
  const {
    windowMs,
    max,
    keyPrefix = "rl",
    keyGenerator = (req) => req.ip || "unknown",
  } = config;

  const windowSec = Math.ceil(windowMs / 1000);

  return async (req: Request, res: Response, next: NextFunction) => {
    const key = `${keyPrefix}:${keyGenerator(req)}`;

    try {
      // INCR and EXPIRE run in one MULTI so a crash between them can
      // never leave a counter without a TTL. NX only sets the TTL on
      // the first request of the window.
      const results = await redis
        .multi()
        .incr(key)
        .expire(key, windowSec, "NX")
        .ttl(key)
        .exec();

      if (!results) throw new Error("Rate limit transaction aborted");

      const current = results[0][1] as number;
      const ttl = results[2][1] as number;

      // Set rate limit headers
      res.setHeader("X-RateLimit-Limit", max);
      res.setHeader("X-RateLimit-Remaining", Math.max(0, max - current));
      res.setHeader("X-RateLimit-Reset", Math.ceil(Date.now() / 1000) + ttl);

      if (current > max) {
        throw AppError.tooMany(
          `Rate limit exceeded. Try again in ${ttl}s`
        );
      }

      next();
    } catch (err) {
      if (err instanceof AppError) throw err;
      // Redis down → fail open (allow the request)
      console.error("Rate limiter error:", err);
      next();
    }
  };
}

// Pre-configured limiters for common routes
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // 20 attempts per 15 min
  keyPrefix: "rl:auth",
});

export const strictLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // 5 attempts per minute (for login/register)
  keyPrefix: "rl:strict",
});

export const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100, // 100 requests per minute for verified users
  keyPrefix: "rl:api",
  keyGenerator: (req) => req.user?.sub || req.apiKey?.clientId || req.ip || "unknown",
});
