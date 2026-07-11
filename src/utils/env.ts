import "dotenv/config";
import { z } from "zod";

const envSchema = z
  .object({
    PORT: z.coerce.number().default(5300),
    NODE_ENV: z.enum(["development", "production"]).default("development"),
    DATABASE_URL: z.string().url(),
    REDIS_URL: z.string().default("redis://localhost:6379/3"),

    // JWT signing. Prefer EdDSA keys for local verification via JWKS.
    JWT_SECRET: z.string().min(32),
    JWT_PRIVATE_KEY: z.string().optional(),
    JWT_PUBLIC_KEY: z.string().optional(),
    JWT_KEY_ID: z.string().default("identity-platform-v1"),
    JWT_ISSUER: z.string().optional(),
    JWT_ACCESS_EXPIRY: z.string().default("15m"),
    JWT_REFRESH_EXPIRY_DAYS: z.coerce.number().default(7),
    REFRESH_RETRY_GRACE_SECONDS: z.coerce.number().int().min(1).max(60).default(10),

    // Browser origins allowed by CORS in production, comma separated.
    // Entries like *.example.com allow all subdomains. When unset,
    // cross-origin browser requests are refused in production.
    CORS_ORIGINS: z.string().optional(),

    // Admin key for client registration
    ADMIN_KEY: z.string().min(1),

    // Audit rows older than this are pruned by the daily cleanup job
    AUDIT_RETENTION_DAYS: z.coerce.number().default(365),

    // Outgoing email for password reset and verification.
    // console logs mails, smtp delivers them, memory buffers them for tests.
    MAIL_PROVIDER: z.enum(["console", "smtp", "memory"]).default("console"),
    SMTP_URL: z.string().optional(),
    MAIL_FROM: z.string().default("Identity Platform <no-reply@localhost>"),

    // OAuth providers (optional — enable as needed)
    GOOGLE_CLIENT_ID: z.string().optional(),
    GOOGLE_CLIENT_SECRET: z.string().optional(),
    GITHUB_CLIENT_ID: z.string().optional(),
    GITHUB_CLIENT_SECRET: z.string().optional(),

    // Service URL (for OAuth callbacks and the default JWT issuer)
    SERVICE_URL: z.string().default("http://localhost:5300"),
  })
  .refine(
    (value) => Boolean(value.JWT_PRIVATE_KEY) === Boolean(value.JWT_PUBLIC_KEY),
    "JWT_PRIVATE_KEY and JWT_PUBLIC_KEY must be configured together"
  )
  .refine(
    (value) => value.MAIL_PROVIDER !== "smtp" || Boolean(value.SMTP_URL),
    "SMTP_URL is required when MAIL_PROVIDER is smtp"
  )
  // The HS256 fallback exists for trying things out, never for real
  // deployments: production refuses to start without signing keys
  .refine(
    (value) => value.NODE_ENV !== "production" || Boolean(value.JWT_PRIVATE_KEY),
    "JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are required in production, the HS256 fallback is development only"
  );

export function parseEnv(
  source: Record<string, string | undefined>
): z.infer<typeof envSchema> {
  return envSchema.parse(source);
}

export const env = parseEnv(process.env);
export type Env = z.infer<typeof envSchema>;

// Issuer baked into and required from every JWT. Defaults to the
// service hostname so each deployment gets its own issuer.
export const jwtIssuer = env.JWT_ISSUER ?? new URL(env.SERVICE_URL).hostname;
