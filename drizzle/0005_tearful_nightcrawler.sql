CREATE TABLE "audit_logs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"client_id" uuid NOT NULL,
	"action" varchar(64) NOT NULL,
	"actor_type" varchar(16) NOT NULL,
	"actor_id" uuid,
	"target_type" varchar(16),
	"target_id" uuid,
	"ip" varchar(45),
	"user_agent" text,
	"details" jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "audit_logs_client_created_idx" ON "audit_logs" USING btree ("client_id","created_at");--> statement-breakpoint
CREATE INDEX "audit_logs_client_action_idx" ON "audit_logs" USING btree ("client_id","action");--> statement-breakpoint
CREATE INDEX "audit_logs_created_idx" ON "audit_logs" USING btree ("created_at");