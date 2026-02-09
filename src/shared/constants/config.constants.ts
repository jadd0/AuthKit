/** List of supported database types */
export const DATABASE_TYPES = ["postgresql", "mysql"] as const;

/** List of supported authentication providers */
export const PROVIDERS = ["emailPassword", "google"] as const;

/** Default idle TTL for sessions in seconds (9 hours) */
export const DEFAULT_IDLE_TTL = 32400;

/** Default absolute TTL for sessions in seconds (7 days) */
export const DEFAULT_ABSOLUTE_TTL = 604800;

export const CSRF_TOKEN_MAX_AGE = 3600000; // 1 hour in milliseconds
