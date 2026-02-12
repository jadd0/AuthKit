import { NextResponse } from "next/server";

/** Adds security headers to a response */
export function addSecurityHeaders(response: Response | NextResponse): Response {
  const isProduction = process.env.NODE_ENV === "production";

  // Content Security Policy - prevents XSS
  response.headers.set(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self'",
      "connect-src 'self'",
      "frame-ancestors 'none'",
    ].join("; "),
  );

  // Force HTTPS in production
  if (isProduction) {
    response.headers.set(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains; preload",
    );
  }

  // Prevent MIME sniffing
  response.headers.set("X-Content-Type-Options", "nosniff");

  // XSS Protection
  response.headers.set("X-XSS-Protection", "1; mode=block");

  // Prevent clickjacking
  response.headers.set("X-Frame-Options", "DENY");

  // Referrer Policy
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");

  // Permissions Policy
  response.headers.set(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=()",
  );

  return response;
}

/** Convenience wrapper for creating secure responses */
export function secureResponse(
  data: any,
  options?: { status?: number; headers?: Headers },
): Response {
  const response = NextResponse.json(data, {
    status: options?.status || 200,
    headers: options?.headers,
  });

  return addSecurityHeaders(response);
}
