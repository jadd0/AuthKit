export * from "./index.js";
import { AuthConfig } from "../shared/types/config.types.js";

/** Used in a user's "auth.ts" or corresponding file to assist them with authentication setup */
export type { AuthConfig };

/** Necessary database type for migrations and auth setup */
export type { DatabaseConfig } from "../shared/types/config.types.js";

/** Main entry point to library */
export { default as AuthKit } from "./core/factory.js";

/** Useful functions and such for use server-side */
export * from "./public";
