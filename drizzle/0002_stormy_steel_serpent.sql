ALTER TABLE "clients" ALTER COLUMN "client_secret_hash" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "clients" ADD COLUMN "is_public" boolean DEFAULT false NOT NULL;