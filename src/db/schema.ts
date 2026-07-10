import {
  pgTable,
  uuid,
  varchar,
  text,
  boolean,
  timestamp,
  primaryKey,
  uniqueIndex,
  index,
  jsonb,
} from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";

// ─── Clients (multi-tenant apps) ───────────────────────────────────

export const clients = pgTable("clients", {
  id: uuid("id").defaultRandom().primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  clientId: varchar("client_id", { length: 64 }).notNull().unique(),
  // Null for public clients (SPAs, mobile apps), which have no secret
  // and must use PKCE for OAuth flows
  clientSecretHash: text("client_secret_hash"),
  isPublic: boolean("is_public").default(false).notNull(),
  // When false, /auth/register is closed and users are provisioned
  // through the user management API instead (invite flow)
  allowUserRegistration: boolean("allow_user_registration").default(true).notNull(),
  redirectUris: text("redirect_uris").array().default([]),
  // Registered pages in the consuming app that receive emailed tokens.
  // Links are only ever built from these, never from request input,
  // so a public client id can't be abused to send phishing links.
  passwordResetUrl: text("password_reset_url"),
  emailVerifyUrl: text("email_verify_url"),
  isActive: boolean("is_active").default(true).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const clientsRelations = relations(clients, ({ many }) => ({
  users: many(users),
  roles: many(roles),
  permissions: many(permissions),
  apiKeys: many(apiKeys),
  serviceAccounts: many(serviceAccounts),
}));

// ─── Users ─────────────────────────────────────────────────────────

export const users = pgTable(
  "users",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    clientId: uuid("client_id")
      .notNull()
      .references(() => clients.id, { onDelete: "cascade" }),
    email: varchar("email", { length: 320 }).notNull(),
    passwordHash: text("password_hash"), // null for OAuth-only users
    oauthProvider: varchar("oauth_provider", { length: 32 }),
    oauthProviderId: varchar("oauth_provider_id", { length: 255 }),
    emailVerified: boolean("email_verified").default(false).notNull(),
    isActive: boolean("is_active").default(true).notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull(),
  },
  (table) => [
    // Same email can exist under different clients
    uniqueIndex("users_client_email_idx").on(table.clientId, table.email),
    index("users_oauth_idx").on(table.oauthProvider, table.oauthProviderId),
  ]
);

export const usersRelations = relations(users, ({ one, many }) => ({
  client: one(clients, { fields: [users.clientId], references: [clients.id] }),
  userRoles: many(userRoles),
  refreshTokens: many(refreshTokens),
}));

// ─── Roles (per-client) ───────────────────────────────────────────

export const roles = pgTable(
  "roles",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    clientId: uuid("client_id")
      .notNull()
      .references(() => clients.id, { onDelete: "cascade" }),
    name: varchar("name", { length: 100 }).notNull(),
    description: text("description"),
    isDefault: boolean("is_default").default(false).notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    // Role names unique per client
    uniqueIndex("roles_client_name_idx").on(table.clientId, table.name),
  ]
);

export const rolesRelations = relations(roles, ({ one, many }) => ({
  client: one(clients, { fields: [roles.clientId], references: [clients.id] }),
  rolePermissions: many(rolePermissions),
  userRoles: many(userRoles),
  serviceAccountRoles: many(serviceAccountRoles),
}));

// ─── Permissions (per-client resource:action pairs) ──────────────

export const permissions = pgTable(
  "permissions",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    clientId: uuid("client_id")
      .notNull()
      .references(() => clients.id, { onDelete: "cascade" }),
    resource: varchar("resource", { length: 100 }).notNull(),
    action: varchar("action", { length: 50 }).notNull(),
    description: text("description"),
  },
  (table) => [
    uniqueIndex("permissions_client_resource_action_idx").on(
      table.clientId,
      table.resource,
      table.action
    ),
  ]
);

export const permissionsRelations = relations(permissions, ({ one, many }) => ({
  client: one(clients, {
    fields: [permissions.clientId],
    references: [clients.id],
  }),
  rolePermissions: many(rolePermissions),
}));

// ─── Role ↔ Permission (junction) ────────────────────────────────

export const rolePermissions = pgTable(
  "role_permissions",
  {
    roleId: uuid("role_id")
      .notNull()
      .references(() => roles.id, { onDelete: "cascade" }),
    permissionId: uuid("permission_id")
      .notNull()
      .references(() => permissions.id, { onDelete: "cascade" }),
  },
  (table) => [primaryKey({ columns: [table.roleId, table.permissionId] })]
);

export const rolePermissionsRelations = relations(
  rolePermissions,
  ({ one }) => ({
    role: one(roles, {
      fields: [rolePermissions.roleId],
      references: [roles.id],
    }),
    permission: one(permissions, {
      fields: [rolePermissions.permissionId],
      references: [permissions.id],
    }),
  })
);

// ─── User ↔ Role (junction, scoped to client) ────────────────────

export const userRoles = pgTable(
  "user_roles",
  {
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    roleId: uuid("role_id")
      .notNull()
      .references(() => roles.id, { onDelete: "cascade" }),
    clientId: uuid("client_id")
      .notNull()
      .references(() => clients.id, { onDelete: "cascade" }),
    assignedAt: timestamp("assigned_at").defaultNow().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.userId, table.roleId, table.clientId] }),
  ]
);

export const userRolesRelations = relations(userRoles, ({ one }) => ({
  user: one(users, { fields: [userRoles.userId], references: [users.id] }),
  role: one(roles, { fields: [userRoles.roleId], references: [roles.id] }),
  client: one(clients, {
    fields: [userRoles.clientId],
    references: [clients.id],
  }),
}));

// ─── Service Accounts (role-bearing machine principals) ───────────

export const serviceAccounts = pgTable(
  "service_accounts",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    clientId: uuid("client_id")
      .notNull()
      .references(() => clients.id, { onDelete: "cascade" }),
    name: varchar("name", { length: 255 }).notNull(),
    description: text("description"),
    isActive: boolean("is_active").default(true).notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("service_accounts_client_name_idx").on(
      table.clientId,
      table.name
    ),
  ]
);

export const serviceAccountsRelations = relations(
  serviceAccounts,
  ({ one, many }) => ({
    client: one(clients, {
      fields: [serviceAccounts.clientId],
      references: [clients.id],
    }),
    serviceAccountRoles: many(serviceAccountRoles),
    apiKeys: many(apiKeys),
  })
);

export const serviceAccountRoles = pgTable(
  "service_account_roles",
  {
    serviceAccountId: uuid("service_account_id")
      .notNull()
      .references(() => serviceAccounts.id, { onDelete: "cascade" }),
    roleId: uuid("role_id")
      .notNull()
      .references(() => roles.id, { onDelete: "cascade" }),
    clientId: uuid("client_id")
      .notNull()
      .references(() => clients.id, { onDelete: "cascade" }),
    assignedAt: timestamp("assigned_at").defaultNow().notNull(),
  },
  (table) => [
    primaryKey({
      columns: [table.serviceAccountId, table.roleId, table.clientId],
    }),
  ]
);

export const serviceAccountRolesRelations = relations(
  serviceAccountRoles,
  ({ one }) => ({
    serviceAccount: one(serviceAccounts, {
      fields: [serviceAccountRoles.serviceAccountId],
      references: [serviceAccounts.id],
    }),
    role: one(roles, {
      fields: [serviceAccountRoles.roleId],
      references: [roles.id],
    }),
    client: one(clients, {
      fields: [serviceAccountRoles.clientId],
      references: [clients.id],
    }),
  })
);

// ─── Refresh Tokens ───────────────────────────────────────────────

export const refreshTokens = pgTable(
  "refresh_tokens",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull().unique(),
    ipAddress: varchar("ip_address", { length: 45 }),
    userAgent: text("user_agent"),
    revoked: boolean("revoked").default(false).notNull(),
    // Why it was revoked: rotated | retry | logout | user_revoked | security.
    // Only replay of a rotated token means two parties held it, so
    // only that reason triggers family revocation. Null (legacy rows)
    // is treated as rotated.
    revokedReason: varchar("revoked_reason", { length: 16 }),
    // Retry proof and the current unused successor for ADR 0010.
    // The operation id and refresh token remain stored only as hashes.
    rotationOperationHash: text("rotation_operation_hash"),
    rotatedAt: timestamp("rotated_at"),
    replacedByTokenId: uuid("replaced_by_token_id"),
    expiresAt: timestamp("expires_at").notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    index("refresh_tokens_user_idx").on(table.userId),
    index("refresh_tokens_expires_idx").on(table.expiresAt),
  ]
);

export const refreshTokensRelations = relations(refreshTokens, ({ one }) => ({
  user: one(users, {
    fields: [refreshTokens.userId],
    references: [users.id],
  }),
}));

// ─── Account Tokens (password reset, email verification) ─────────

export const accountTokens = pgTable(
  "account_tokens",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    purpose: varchar("purpose", { length: 32 }).notNull(),
    tokenHash: text("token_hash").notNull().unique(),
    expiresAt: timestamp("expires_at").notNull(),
    usedAt: timestamp("used_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [index("account_tokens_user_idx").on(table.userId)]
);

export const accountTokensRelations = relations(accountTokens, ({ one }) => ({
  user: one(users, {
    fields: [accountTokens.userId],
    references: [users.id],
  }),
}));

// ─── API Keys ─────────────────────────────────────────────────────

export const apiKeys = pgTable(
  "api_keys",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    clientId: uuid("client_id")
      .notNull()
      .references(() => clients.id, { onDelete: "cascade" }),
    serviceAccountId: uuid("service_account_id").references(
      () => serviceAccounts.id,
      { onDelete: "cascade" }
    ),
    keyPrefix: varchar("key_prefix", { length: 12 }).notNull(),
    keyHash: text("key_hash").notNull(),
    name: varchar("name", { length: 255 }).notNull(),
    scopes: text("scopes").array().default([]),
    revoked: boolean("revoked").default(false).notNull(),
    expiresAt: timestamp("expires_at"),
    lastUsedAt: timestamp("last_used_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    index("api_keys_client_idx").on(table.clientId),
    // Lookups during authentication are by hash, never by prefix
    uniqueIndex("api_keys_key_hash_idx").on(table.keyHash),
  ]
);

export const apiKeysRelations = relations(apiKeys, ({ one }) => ({
  client: one(clients, {
    fields: [apiKeys.clientId],
    references: [clients.id],
  }),
  serviceAccount: one(serviceAccounts, {
    fields: [apiKeys.serviceAccountId],
    references: [serviceAccounts.id],
  }),
}));

// ─── Audit Logs (append only, see docs/contracts/audit.md) ───────

export const auditLogs = pgTable(
  "audit_logs",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    // No FK cascade: audit rows must survive the deletion of what
    // they describe, history outlives state
    clientId: uuid("client_id").notNull(),
    action: varchar("action", { length: 64 }).notNull(),
    actorType: varchar("actor_type", { length: 16 }).notNull(),
    actorId: uuid("actor_id"),
    targetType: varchar("target_type", { length: 16 }),
    targetId: uuid("target_id"),
    ip: varchar("ip", { length: 45 }),
    userAgent: text("user_agent"),
    details: jsonb("details"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    // The read API filters by client and pages newest first
    index("audit_logs_client_created_idx").on(table.clientId, table.createdAt),
    index("audit_logs_client_action_idx").on(table.clientId, table.action),
    // Retention pruning scans by age alone
    index("audit_logs_created_idx").on(table.createdAt),
  ]
);

// ─── Type exports ─────────────────────────────────────────────────

export type Client = typeof clients.$inferSelect;
export type NewClient = typeof clients.$inferInsert;
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type Role = typeof roles.$inferSelect;
export type Permission = typeof permissions.$inferSelect;
export type ServiceAccount = typeof serviceAccounts.$inferSelect;
export type RefreshToken = typeof refreshTokens.$inferSelect;
export type ApiKey = typeof apiKeys.$inferSelect;
export type AuditLog = typeof auditLogs.$inferSelect;
export type NewAuditLog = typeof auditLogs.$inferInsert;
