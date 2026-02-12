// src/shared/utils/security/redirectValidator.ts

import { logger } from "@/server/classes/AuthKitLogger";

/**
 * Strict redirect URI validation for OAuth 2.1 compliance
 *
 * OAuth 2.1 requires EXACT matching of redirect URIs to prevent:
 * - Open redirect attacks
 * - Subdomain takeover attacks (evil.example.com)
 * - Path traversal attacks (../admin)
 * - Protocol downgrade attacks (http vs https)
 * - Port manipulation attacks
 *
 * Spec: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
 */

export interface RedirectValidationResult {
  valid: boolean;
  reason?: string;
}

/**
 * OAuth callback parameters that are allowed (added by OAuth provider)
 * These are the only query params that can appear in callback URLs
 */
const OAUTH_CALLBACK_PARAMS = [
  "code", // Authorization code
  "state", // CSRF token
  "error", // Error code
  "error_description", // Human-readable error
  "error_uri", // Link to error documentation
  "iss", // Issuer identifier (OAuth 2.0 security extension)
];

/**
 * Validate that a redirect URI exactly matches one in the allowlist
 *
 * Per OAuth 2.1: "The authorization server MUST require exact matching of redirect URIs"
 *
 * @param redirectUri - The redirect URI to validate
 * @param allowedRedirects - Array of pre-registered allowed redirect URIs
 * @returns Validation result with reason if invalid
 */
export function validateRedirectUri(
  redirectUri: string,
  allowedRedirects: string[],
): RedirectValidationResult {
  // 1. Basic validation
  if (!redirectUri) {
    return {
      valid: false,
      reason: "Redirect URI is required",
    };
  }

  if (!allowedRedirects || allowedRedirects.length === 0) {
    return {
      valid: false,
      reason: "No allowed redirect URIs configured (security misconfiguration)",
    };
  }

  // 2. Parse the redirect URI
  let redirectUrl: URL;
  try {
    redirectUrl = new URL(redirectUri);
  } catch (e) {
    return {
      valid: false,
      reason: `Invalid redirect URI format: ${redirectUri}`,
    };
  }

  // 3. Security check: HTTPS required in production (except localhost)
  const isLocalhost =
    redirectUrl.hostname === "localhost" ||
    redirectUrl.hostname === "127.0.0.1" ||
    redirectUrl.hostname === "[::1]";

  if (
    redirectUrl.protocol === "http:" &&
    !isLocalhost &&
    process.env.NODE_ENV === "production"
  ) {
    return {
      valid: false,
      reason: "HTTP redirect URIs are not allowed in production (use HTTPS)",
    };
  }

  // 4. Check against allowlist
  for (const allowed of allowedRedirects) {
    let allowedUrl: URL;

    try {
      allowedUrl = new URL(allowed);
    } catch (e) {
      // Skip invalid entries in allowlist (log in production)
      if (process.env.NODE_ENV !== "test") {
        logger.warn(`Invalid allowed redirect URI in config: ${allowed}`);
      }
      continue;
    }

    // 5. Exact matching: protocol, hostname, port, pathname
    if (
      redirectUrl.protocol !== allowedUrl.protocol ||
      redirectUrl.hostname !== allowedUrl.hostname ||
      redirectUrl.port !== allowedUrl.port ||
      redirectUrl.pathname !== allowedUrl.pathname
    ) {
      continue; // No match, try next
    }

    // 6. Query parameter validation
    // OAuth callback URLs can only have params added by the OAuth provider
    const redirectParams = Array.from(redirectUrl.searchParams.keys());
    const allowedUrlParams = Array.from(allowedUrl.searchParams.keys());

    // If allowlist URL has specific params, they must match exactly
    if (allowedUrlParams.length > 0) {
      // Check all params match
      let exactMatch = true;

      if (redirectParams.length !== allowedUrlParams.length) {
        exactMatch = false;
      } else {
        for (const param of allowedUrlParams) {
          if (
            redirectUrl.searchParams.get(param) !==
            allowedUrl.searchParams.get(param)
          ) {
            exactMatch = false;
            break;
          }
        }
      }

      // No match, try next
      if (!exactMatch) {
        continue;
      }
    } else {
      // Allowlist URL has no params
      // Redirect can only have standard OAuth callback params
      const extraParams = redirectParams.filter(
        (p) => !OAUTH_CALLBACK_PARAMS.includes(p),
      );

      if (extraParams.length > 0) {
        // Has non-OAuth params - reject
        continue;
      }
    }

    // 7. Fragment validation (should typically be empty in OAuth)
    // Some providers use fragments for errors, but they should match if present
    if (allowedUrl.hash && redirectUrl.hash !== allowedUrl.hash) {
      continue;
    }

    // All checks passed - valid redirect
    return { valid: true };
  }

  // No match found in allowlist
  return {
    valid: false,
    reason:
      `Redirect URI "${redirectUri}" does not match any allowed redirect.\n` +
      `\nAllowed redirects:\n${allowedRedirects.map((u) => `  - ${u}`).join("\n")}\n` +
      `\nCommon issues:\n` +
      `  • Protocol mismatch (http vs https)\n` +
      `  • Hostname mismatch (check subdomains exactly)\n` +
      `  • Port mismatch (443 vs 8080)\n` +
      `  • Path mismatch (/callback vs /auth/callback)\n` +
      `  • Query parameter mismatch\n` +
      `\nOAuth 2.1 requires EXACT matching for security.`,
  };
}

/**
 * Assert that a redirect URI is valid (fail-closed)
 * Throws an error if validation fails
 *
 * Use this in production code to enforce redirect validation
 *
 * @param redirectUri - URI to validate
 * @param allowedRedirects - Allowlist of valid redirect URIs
 * @param context - Context for error message (e.g., "OAuth callback")
 * @throws Error if validation fails
 *
 * @example
 * assertRedirectValid(
 *   'https://app.example.com/callback',
 *   ['https://app.example.com/callback'],
 *   'OIDC authorization'
 * );
 */
export function assertRedirectValid(
  redirectUri: string,
  allowedRedirects: string[],
  context: string = "Redirect",
): void {
  const result = validateRedirectUri(redirectUri, allowedRedirects);

  if (!result.valid) {
    throw new Error(
      `[AuthKit] ${context} validation failed\n\n${result.reason}\n\n` +
        `This is a security measure to prevent open redirect attacks.\n` +
        `If "${redirectUri}" is legitimate, add it to allowedRedirectURIs in your provider config.`,
    );
  }
}

/**
 * Check if a redirect URI is valid (non-throwing version)
 *
 * Use this for conditional logic or startup validation
 *
 * @param redirectUri - URI to validate
 * @param allowedRedirects - Allowlist
 * @returns true if valid, false otherwise
 *
 * @example
 * if (!isRedirectValid(uri, allowlist)) {
 *   console.error('Invalid redirect configuration');
 * }
 */
export function isRedirectValid(
  redirectUri: string,
  allowedRedirects: string[],
): boolean {
  const result = validateRedirectUri(redirectUri, allowedRedirects);
  return result.valid;
}
