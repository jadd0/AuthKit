import { routeMainAuthRequest } from "@/server/routes";
import { addSecurityHeaders } from "@/shared/utils/addSecurityHeaders";
import { NextRequest, NextResponse } from "next/server";

// TODO: make so checks for edge and node environments
// TODO: check incoming ip address against trusted proxies

/**
 * Core auth router used by all HTTP entrypoints.
 * Works with standard Web Request/Response.
 */
export async function routeAuthRequest(req: NextRequest): Promise<Response> {
  const url = new URL(req.url);
  const method = req.method;

  const body = await req.json().catch(() => ({}));
  const path = url.pathname; // e.g. /api/auth/provider/emailPassword/login

  const cookies = req.headers.get("cookie") || "";
  const parsedCookies = Object.fromEntries(
    cookies.split("; ").map((c) => {
      const [key, ...v] = c.split("=");
      return [key, v.join("=")];
    }),
  );

  // Split, remove empty, `api`, and `auth`
  const segments = path
    .split("/")
    .filter((s) => s.length > 0 && s !== "api" && s !== "auth");

  // Handle different routes based on the path segments
  const response = await routeMainAuthRequest(
    segments,
    method,
    { body, url: req.url, request: req },
    parsedCookies,
  );

  // ALWAYS add security headers to every response
  return addSecurityHeaders(
    NextResponse.json(await response.json(), {
      status: response.status,
      headers: response.headers,
    }),
  );
}
