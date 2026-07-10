ALTER TABLE "refresh_tokens" ADD COLUMN "rotation_operation_hash" text;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD COLUMN "rotated_at" timestamp;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD COLUMN "replaced_by_token_id" uuid;