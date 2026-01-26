import { z } from "zod";

/** Runtime validation: is a function */
const IsFunction = z.custom<Function>((v) => typeof v === "function", {
  message: "Expected a function",
});

/** Callbacks schema using function check */
const CallbacksSchema = z
  .object({
    authorise: IsFunction.optional(),
  })
  .default({});

/** Schema to validate database as a pool (alternate as URL defined inside AuthConfigSchema) */
export const DatabasePoolConfigSchema = z.object({
  user: z.string(),
  host: z.string(),
  password: z.string(),
  database: z.string(),
  port: z.number(),
});

/** Options schema for options (duh) */
const OptionsSchema = z.object({
  strategy: z.enum(["jwt", "database"]).default("database"),
  idleTTL: z.number().nullable().optional(),
  absoluteTTL: z.number().nullable().optional(),
  sameSite: z
    .enum(["lax", "strict", "none"])
    .default("strict")
    .nullable()
    .optional(),
  loginRoute: z.string().nullable().optional(), // Optional value for an automatic redirect to login page
  redirectURLs: z.enum([]).optional(), // Optional array for OIDC provider redirect URLs
  stateSecret: z.string().min(8), // Secret used to sign OIDC state payloads
  roles: z.array(z.string()), // Array of valid user roles
});

/**
 * Provider schemas
 *
 * Design: discriminate on 'id'
 * in user code ("google", "emailPassword", etc.).
 */

// Credentials provider – minimal,
const CredentialsProviderSchema = z.object({
  type: z.literal("credentials"),
  id: z.literal("emailPassword"),
});

// Google provider – minimal, you do NOT have to pass issuer/scopes
const GoogleProviderSchema = z.object({
  type: z.literal("oidc"),
  id: z.literal("google"),
  clientId: z.string(),
  clientSecret: z.string(),
  issuer: z.string().optional(),
  redirectURI: z.string().optional(),
  scopes: z.array(z.string()).optional(),
});

// Generic OIDC provider for any other id
const GenericOIDCProviderSchema = z.object({
  type: z.literal("oidc"),
  id: z.string().min(1), // any non-empty id
  issuer: z.string(),
  clientId: z.string(),
  clientSecret: z.string(),
  redirectURI: z.string().optional(),
  scopes: z.array(z.string()).optional(),
});

/**
 * Union of all providers
 *
 * With discriminatedUnion on `type`, "oidc" would have to be one unified schema.
 * With discriminatedUnion on `id`, GenericOIDCProviderSchema would need a literal id.
 */
const ProviderSchema = z.union([
  CredentialsProviderSchema,
  GoogleProviderSchema,
  GenericOIDCProviderSchema,
]);

/** Full config schema */
export const AuthConfigSchema = z.object({
  options: OptionsSchema,

  /** Default roles assigned to new users */
  userRoles: z.array(z.string()).default(["user", "admin"]).optional(),

  /** Either a database pool, or a database URL */
  db: z.union([z.string().url(), DatabasePoolConfigSchema]),

  providers: z.array(ProviderSchema).default([]),
  callbacks: CallbacksSchema,
});
