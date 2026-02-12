type LogLevel = "debug" | "info" | "warn" | "error";

/**
 * Patterns for sensitive data that should be redacted
 */
const SENSITIVE_PATTERNS = {
  // Session tokens (base64url, typically 32-64 chars)
  sessionToken: /\b[A-Za-z0-9_-]{32,128}\b/g,

  // JWT tokens (three base64url parts separated by dots)
  jwt: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,

  // Bearer tokens in Authorisation headers
  bearerToken: /Bearer\s+[A-Za-z0-9_.\-]+/gi,

  // OAuth codes (authorization codes, typically 20-128 chars)
  authCode: /[?&]code=([A-Za-z0-9_\-\.~]+)/gi,

  // Access/refresh tokens in query params or JSON
  accessToken:
    /(access_token|refresh_token|id_token)["']?\s*[:=]\s*["']?([A-Za-z0-9_.\-]+)["']?/gi,

  // API keys (common formats)
  apiKey:
    /(api[_-]?key|apikey|client[_-]?secret)["']?\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})["']?/gi,

  // Passwords in JSON or form data
  password: /(password|passwd|pwd)["']?\s*[:=]\s*["']?([^"'\s&,}]+)["']?/gi,

  // Code verifier/challenge (PKCE)
  pkce: /(code_verifier|code_challenge)["']?\s*[:=]\s*["']?([A-Za-z0-9_\-]{43,128})["']?/gi,

  // Email addresses (optional, but good for privacy)
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,

  // Credit card numbers (just in case)
  creditCard: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
};

/**
 * Fields in objects that should always be redacted
 */
const SENSITIVE_FIELD_NAMES = [
  "password",
  "passwd",
  "pwd",
  "secret",
  "token",
  "accessToken",
  "refreshToken",
  "idToken",
  "sessionToken",
  "apiKey",
  "clientSecret",
  "privateKey",
  "codeVerifier",
  "codeChallenge",
  "authorization",
  "cookie",
  "set-cookie",
];

/**
 * Redact sensitive information from a string
 */
function redactString(input: string): string {
  let redacted = input;

  // Apply all pattern-based redactions
  for (const [name, pattern] of Object.entries(SENSITIVE_PATTERNS)) {
    redacted = redacted.replace(pattern, (match, ...groups) => {
      // For patterns with capture groups, preserve the key and redact the value
      if (groups.length > 0 && groups[0]) {
        const capturedValue = groups[0];
        // Preserve first/last 4 chars for debugging (if long enough)
        if (capturedValue.length > 8) {
          const preview = `${capturedValue.slice(0, 4)}...${capturedValue.slice(-4)}`;
          return match.replace(capturedValue, `[REDACTED:${preview}]`);
        }
        return match.replace(capturedValue, "[REDACTED]");
      }
      // For patterns without groups, redact the entire match
      return "[REDACTED]";
    });
  }

  return redacted;
}

/**
 * Deep clone and redact sensitive fields in objects
 */
function redactObject(obj: any, depth = 0): any {
  // Prevent infinite recursion
  if (depth > 10) return "[MAX_DEPTH_EXCEEDED]";

  // Handle null/undefined
  if (obj === null || obj === undefined) return obj;

  // Handle primitive types
  if (typeof obj !== "object") {
    return typeof obj === "string" ? redactString(obj) : obj;
  }

  // Handle arrays
  if (Array.isArray(obj)) {
    return obj.map((item) => redactObject(item, depth + 1));
  }

  // Handle objects
  const redactedObj: any = {};
  for (const [key, value] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase();

    // Check if field name is sensitive
    const isSensitiveField = SENSITIVE_FIELD_NAMES.some((sensitiveKey) =>
      lowerKey.includes(sensitiveKey.toLowerCase()),
    );

    if (isSensitiveField) {
      // Fully redact sensitive fields
      if (typeof value === "string" && value.length > 8) {
        redactedObj[key] =
          `[REDACTED:${value.slice(0, 4)}...${value.slice(-4)}]`;
      } else {
        redactedObj[key] = "[REDACTED]";
      }
    } else if (typeof value === "string") {
      // Apply pattern-based redaction to string values
      redactedObj[key] = redactString(value);
    } else if (typeof value === "object" && value !== null) {
      // Recursively redact nested objects
      redactedObj[key] = redactObject(value, depth + 1);
    } else {
      // Keep primitives as-is
      redactedObj[key] = value;
    }
  }

  return redactedObj;
}

/**
 * Process arguments for logging - redact sensitive data
 */
function processLogArgs(args: any[]): any[] {
  return args.map((arg) => {
    // Handle Error objects specially
    if (arg instanceof Error) {
      return {
        name: arg.name,
        message: redactString(arg.message),
        stack: arg.stack ? redactString(arg.stack) : undefined,
      };
    }

    // Handle objects
    if (typeof arg === "object" && arg !== null) {
      return redactObject(arg);
    }

    // Handle strings
    if (typeof arg === "string") {
      return redactString(arg);
    }

    // Return primitives as-is
    return arg;
  });
}

/**
 * Custom logger for AuthKit with automatic redaction of sensitive data
 */
export class AuthKitLogger {
  private enabled: boolean;
  private redactionEnabled: boolean;

  constructor() {
    this.enabled =
      process.env.NODE_ENV === "development" ||
      process.env.AUTHKIT_DEBUG === "true";

    // Allow disabling redaction for local debugging
    this.redactionEnabled = process.env.AUTHKIT_DISABLE_REDACTION !== "true";
  }

  debug(message: string, ...args: any[]) {
    if (this.enabled) {
      const processedArgs = this.redactionEnabled ? processLogArgs(args) : args;
      console.log(`[AuthKit:Debug]`, redactString(message), ...processedArgs);
    }
  }

  info(message: string, ...args: any[]) {
    if (this.enabled) {
      const processedArgs = this.redactionEnabled ? processLogArgs(args) : args;
      console.log(`[AuthKit:Info]`, redactString(message), ...processedArgs);
    }
  }

  warn(message: string, ...args: any[]) {
    const processedArgs = this.redactionEnabled ? processLogArgs(args) : args;
    console.warn(`[AuthKit:Warn]`, redactString(message), ...processedArgs);
  }

  error(message: string, ...args: any[]) {
    const processedArgs = this.redactionEnabled ? processLogArgs(args) : args;
    console.error(`[AuthKit:Error]`, redactString(message), ...processedArgs);
  }

  /**
   * Explicitly redact a value (for manual use in code)
   */
  redact(value: any): any {
    if (typeof value === "string") {
      return redactString(value);
    }
    return redactObject(value);
  }
}

export const logger = new AuthKitLogger();
