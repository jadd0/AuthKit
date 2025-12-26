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
  redirectURLs: z.enum([]).nullable(), // Optional array for OIDC provider redirect URLs
  stateSecret: z.string().min(8), // Secret used to sign OIDC state payloads
});

/** Schema for OIDC providers */
const OIDCProvidersSchema = z.object({
  id: z.string(),
  type: z.string(),
  issuer: z.string(),
  clientId: z.string(),
  clientSecret: z.string(),
  redirectURI: z.string(),
  scopes: z.enum([]),
});

/** Full config schema */
export const AuthConfigSchema = z.object({
  options: OptionsSchema,

  /** Default roles assigned to new users */
  userRoles: z.array(z.string()).default(["user", "admin"]).optional(),

  /** Either a database pool, or a database URL */
  db: z.union([z.string().url(), DatabasePoolConfigSchema]),

  providers: z.array(OIDCProvidersSchema).default([]),
  callbacks: CallbacksSchema,
});
