import "dotenv/config";
import { z } from "zod";

const envSchema = z.object({
  PORT: z.coerce.number().default(5200),
  NODE_ENV: z.enum(["development", "production"]).default("development"),
  DATABASE_URL: z.string().url(),
  REDIS_URL: z.string().default("redis://localhost:6379/2"),

  // JWT — use EdDSA for speed + small tokens, or HS256 for simplicity
  JWT_SECRET: z.string().min(32),
  JWT_ACCESS_EXPIRY: z.string().default("15m"),
  JWT_REFRESH_EXPIRY_DAYS: z.coerce.number().default(7),

  // Admin key for client registration
  ADMIN_KEY: z.string().min(1),

  // OAuth providers (optional — enable as needed)
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  GITHUB_CLIENT_ID: z.string().optional(),
  GITHUB_CLIENT_SECRET: z.string().optional(),

  // Service URL (for OAuth callbacks)
  SERVICE_URL: z.string().default("https://auth.example.com"),
});

export const env = envSchema.parse(process.env);
export type Env = z.infer<typeof envSchema>;
