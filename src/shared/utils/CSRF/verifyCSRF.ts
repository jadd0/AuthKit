import {
  CSRF_COOKIE_NAME,
  CSRF_HEADER_NAME,
  SESSION_COOKIE_NAME,
} from "@/shared/constants";
import { NextRequest } from "next/server";
import { CSRFTokenPayload, generateCsrfToken } from "./generateCSRFToken";
import { authConfig } from "@/server/core/singleton";
import crypto from "crypto";

const CSRF_TOKEN_MAX_AGE = 3600000; // 1 hour in milliseconds

/** Helper function to verify a CSRF token */
export function verifyCsrf(request: NextRequest, action?: string): boolean {
  const sessionToken = request.cookies.get(SESSION_COOKIE_NAME)?.value;
  const cookieToken = request.cookies.get(CSRF_COOKIE_NAME)?.value;
  const headerToken = request.headers.get(CSRF_HEADER_NAME);

  // If any of the tokens are missing, fail immediately
  if (!sessionToken || !cookieToken || !headerToken) {
    throw new Error("CSRF validation failed: Missing token(s)");
  }

  // Cookie and header tokens must match and be valid for the session token
  if (cookieToken !== headerToken) {
    throw new Error("CSRF validation failed: Token mismatch");
  }

  // Parse token
  const [payloadB64, signature] = headerToken.split(".");

  if (!payloadB64 || !signature) {
    throw new Error("CSRF validation failed: Invalid token format");
  }

  const payloadStr = Buffer.from(payloadB64, "base64").toString("utf-8");
  const payload = JSON.parse(payloadStr) as CSRFTokenPayload;

  // Verify token signature
  const expectedSignature = crypto
    .createHmac("sha256", authConfig.options.CSRFSecret)
    .update(payloadStr)
    .digest("hex");

  if (signature !== expectedSignature) {
    throw new Error("CSRF validation failed: Invalid token signature");
  }

  // Verify session binding
  if (payload.sessionToken !== sessionToken) {
    throw new Error("CSRF validation failed: Session token mismatch");
  }

  const tokenAge = Date.now() - payload.timestamp;
  if (tokenAge > CSRF_TOKEN_MAX_AGE) {
    throw new Error("CSRF validation failed: Token expired");
  }

  // Verify action-specific token if provided
  if (action && payload.actionHash) {
    const expectedActionHash = crypto
      .createHash("sha256")
      .update(action)
      .digest("hex");
    if (payload.actionHash !== expectedActionHash) {
      throw new Error("CSRF validation failed: Action mismatch");
    }
  }

  // Defense in depth: Origin/Referer validation
  if (!verifyOrigin(request)) {
    throw new Error("CSRF validation failed: Origin verification failed");
  }

  return true;
}

/** Helper function to verify the origin of a request */
function verifyOrigin(request: NextRequest): boolean {
  const origin = request.headers.get("origin");
  const referer = request.headers.get("referer");
  const host = request.headers.get("host");

  // Check Origin header (preferred)
  if (origin) {
    const originHost = new URL(origin).host;
    return originHost === host;
  }

  // Fallback to Referer header
  if (referer) {
    const refererHost = new URL(referer).host;
    return refererHost === host;
  }

  // If neither header is present, reject (suspicious)
  return false;
}
