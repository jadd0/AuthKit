/** Ensures only one object of this kind exists and provides a single point of access to it for any other code, rather than a node module - https://refactoring.guru/design-patterns/singleton/typescript/example */

import type { AuthConfig } from "@/server/index";
import { AuthConfigSchema } from "@/shared/validation/server/config.validation";
import { Auth } from "@/server/classes/auth/auth";
import { dbSchemaValidation } from "@/shared/utils/dbSchemaValidation";
import { emailPasswordProviderExport } from "@/server/classes/providers";
import { ServerAuth } from "@/server/classes/auth/server/auth/serverAuth";
import { ServerSession } from "@/server/classes/auth/server/session/serverSession";

// Module-scoped references
let instance: Auth | null = null;
let initPromise: Promise<Auth> | null = null;

export let db: any;
export let authConfig: AuthConfig;
export let auth: Auth;

export let serverAuth: ServerAuth;
export let serverSession: ServerSession;

// Re-export providers for definite instantiation
export const emailPasswordProvider = emailPasswordProviderExport;

/** Normalise and validate configuration, connect DB (Node runtime only), and create the Auth instance */
async function init(config: AuthConfig): Promise<Auth> {
  // Validate config using Zod schema
  const parsed = AuthConfigSchema.safeParse(config);

  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `- ${i.message} (at ${i.path.join(".")})`)
      .join("\n");
    throw new Error(`Invalid auth configuration:\n${issues}`);
  }

  const c = parsed.data;

  // Lazy import node-postgres drizzle only in Node runtime paths

  if (c.db) {
    // Avoid importing on Edge; rely on runtime heuristics
    const isNode =
      typeof process !== "undefined" &&
      typeof process.versions?.node === "string";

    if (!isNode) {
      throw new Error("Database adapter requires Node.js runtime");
    }

    const { drizzle } = await import("drizzle-orm/node-postgres");

    db = drizzle(c.db as any);

    // Test the connection with a simple query
    try {
      await (db as any).execute("SELECT 1");
      console.log("Database connection successful");
    } catch (error) {
      console.error("Database connection failed:", error);
      throw new Error(
        "Failed to connect to the database. Please check your database connection method and credentials. Given method: " +
          (typeof c.db == "string" ? "database URL" : "database Pool")
      );
    }
  }

  // Validate the DB against the schema
  try {
    await dbSchemaValidation();
    console.log("Database Schema validation successful");
  } catch (error: any) {
    console.error("Schema validation error:", error.message);
  }

  // Export the config library-wide
  authConfig = config;

  // Default TTL lengths if not specified by developer
  const idleTTLLength = 1800 * 1000; // 30 minutes
  const absoluteTTLLength = 32400 * 1000; // 9 hours

  // Create the Auth instance
  auth = new Auth(
    c.providers,
    c.callbacks,
    c.options.idleTTL || idleTTLLength,
    c.options.absoluteTTL || absoluteTTLLength
  );

  serverAuth = new ServerAuth();
  serverSession = new ServerSession();

  return auth;
}

/** Get or create the singleton instance in a concurrency-safe way */
export async function getAuthInstance(config: AuthConfig): Promise<Auth> {
  if (instance) return instance; // fast path

  if (initPromise) return initPromise; // de-dupe concurrent first calls

  initPromise = init(config)
    .then((svc) => {
      instance = svc;
      return svc;
    })
    .finally(() => {
      // Clear the promise after resolution/rejection to allow retry if needed
      initPromise = null;
    });

  return initPromise;
}
