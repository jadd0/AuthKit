import {
  CSRF_COOKIE_NAME,
  CSRF_HEADER_NAME,
  SESSION_COOKIE_NAME,
} from "@/shared/constants";
import { NextRequest } from "next/server";
import { generateCsrfToken } from "./generateCSRFToken";

/** Helper function to verify a CSRF token */
export function verifyCsrf(request: NextRequest): void {
  const sessionToken = request.cookies.get(SESSION_COOKIE_NAME)?.value;
  const cookieToken = request.cookies.get(CSRF_COOKIE_NAME)?.value;
  const headerToken = request.headers.get(CSRF_HEADER_NAME);

  // If any of the tokens are missing, fail immediately
  if (!sessionToken || !cookieToken || !headerToken) {
    throw new Error("CSRF validation failed");
  }

  // Generate the expected CSRF token based on the session token
  const expected = generateCsrfToken(sessionToken);

  // Compare what we *expect* with both cookie and header
  if (cookieToken !== expected || headerToken !== expected) {
    throw new Error("CSRF validation failed");
  }
}
