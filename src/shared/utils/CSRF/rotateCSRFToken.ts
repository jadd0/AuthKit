// src/server/public/functions/rotateCsrfToken.ts
import { generateCsrfToken } from "./generateCSRFToken";
import { generateCSRFCookie } from "./generateCSRFCookie";

/** Helper function to rotate a CSRF token for a given session */
export async function rotateCsrfToken(sessionToken: string): Promise<string> {
  const newToken = generateCsrfToken(sessionToken);
  return generateCSRFCookie(newToken);
}
