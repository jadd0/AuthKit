import { NextRequest, NextResponse } from "next/server";

/**
 * Build redirect response with original destination preserved
 */
export function redirectToLogin(
  request: NextRequest,
  loginRoute: string,
  originalPath: string,
): NextResponse {
  const url = request.nextUrl.clone();
  url.pathname = loginRoute;
  url.searchParams.set("redirectTo", originalPath);

  return NextResponse.redirect(url);
}
