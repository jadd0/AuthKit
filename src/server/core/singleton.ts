import type { AuthConfig } from "@/server/index";
import { AuthConfigSchema } from "@/shared/validation/server/config.validation";
import { Auth } from "@/server/classes/auth/auth";
import { dbSchemaValidation } from "@/shared/utils/dbSchemaValidation";
import { emailPasswordProviderExport } from "@/server/classes/providers";
import { ServerAuth } from "@/server/classes/auth/server/auth/serverAuth";
import { ServerSession } from "@/server/classes/auth/server/session/serverSession";
import { logger } from "@/server/classes/AuthKitLogger";

// globalThis instead of module-scoped variables
declare global {
  var __authkit_instance: Auth | null | undefined;
  var __authkit_initPromise: Promise<Auth> | null | undefined;
  var __authkit_db: any;
  var __authkit_config: AuthConfig | undefined;
  var __authkit_serverAuth: ServerAuth | undefined;
  var __authkit_serverSession: ServerSession | undefined;
}

// Initialse if not exists
globalThis.__authkit_instance = globalThis.__authkit_instance ?? null;
globalThis.__authkit_initPromise = globalThis.__authkit_initPromise ?? null;

// Export getters for library-wide access
export const getDb = () => globalThis.__authkit_db;
export const getAuthConfig = () => globalThis.__authkit_config;
export const getAuth = () => globalThis.__authkit_instance;
export const getServerAuth = () => globalThis.__authkit_serverAuth;
export const getServerSession = () => globalThis.__authkit_serverSession;

// Legacy exports
export let db: any;
export let authConfig: AuthConfig;
export let auth: Auth;
export let serverAuth: ServerAuth;
export let serverSession: ServerSession;

export const emailPasswordProvider = emailPasswordProviderExport;

async function init(config: AuthConfig): Promise<Auth> {
  const parsed = AuthConfigSchema.safeParse(config);

  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `- ${i.message} (at ${i.path.join(".")})`)
      .join("\n");
    throw new Error(`Invalid auth configuration:\n${issues}`);
  }

  const c = parsed.data;

  if (c.db) {
    const isNode =
      typeof process !== "undefined" &&
      typeof process.versions?.node === "string";

    if (!isNode) {
      throw new Error("Database adapter requires Node.js runtime");
    }

    const { drizzle } = await import("drizzle-orm/node-postgres");
    db = drizzle(c.db as any);
    globalThis.__authkit_db = db;

    try {
      await (db as any).execute("SELECT 1");
      logger.info("Database connection successful");
    } catch (error) {
      logger.error("Database connection failed:", error);
      throw new Error(
        "Failed to connect to the database. Please check your database connection method and credentials. Given method: " +
          (typeof c.db == "string" ? "database URL" : "database Pool"),
      );
    }
  }

  try {
    await dbSchemaValidation();
  } catch (error: any) {
    logger.error("Schema validation error: ", error.message);
  }

  authConfig = config;
  globalThis.__authkit_config = config;

  const idleTTLLength = 1800 * 1000;
  const absoluteTTLLength = 32400 * 1000;

  auth = new Auth(
    c.providers,
    c.callbacks,
    c.options.idleTTL || idleTTLLength,
    c.options.absoluteTTL || absoluteTTLLength,
  );

  serverAuth = new ServerAuth();
  serverSession = new ServerSession();

  globalThis.__authkit_serverAuth = serverAuth;
  globalThis.__authkit_serverSession = serverSession;

  return auth;
}

export async function getAuthInstance(config?: AuthConfig): Promise<Auth> {
  if (!config) {
    if (globalThis.__authkit_instance) return globalThis.__authkit_instance;

    if (globalThis.__authkit_initPromise) {
      return globalThis.__authkit_initPromise;
    }

    throw new Error(
      "Auth not initialized - call getAuthInstance(config) from a route handler first",
    );
  }

  if (globalThis.__authkit_instance) return globalThis.__authkit_instance;

  if (globalThis.__authkit_initPromise) return globalThis.__authkit_initPromise;

  globalThis.__authkit_initPromise = init(config)
    .then((svc) => {
      globalThis.__authkit_instance = svc;
      return svc;
    })
    .finally(() => {
      globalThis.__authkit_initPromise = null;
    });

  return globalThis.__authkit_initPromise;
}
