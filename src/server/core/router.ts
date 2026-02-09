import { addSecurityHeaders } from "@/shared/utils/addSecurityHeaders";
import { routeProviderRequest } from "../routes/providers";
import { routeSessionRequest } from "../routes/session";
import { NextRequest, NextResponse } from "next/server";

export async function routeMainAuthRequest(
  segments: string[],
  method: string,
  context: { body: any; url: string; request: NextRequest },
  cookies: Record<string, string>,
): Promise<Response> {
  let response: Response;

  try {
    if (segments[0] === "provider") {
      response = await routeProviderRequest(segments, method, context, cookies);
    } else if (segments[0] === "session") {
      response = await routeSessionRequest(segments, method, context, cookies);
    } else {
      response = new Response(JSON.stringify({ message: "Route not found" }), {
        status: 404,
      });
    }
  } catch (error) {
    console.error("Auth route error:", error);

    response = new Response(
      JSON.stringify({ message: "Internal server error" }),
      { status: 500 },
    );
  }

  // ALWAYS add security headers to every response
  return addSecurityHeaders(
    NextResponse.json(await response.json(), {
      status: response.status,
      headers: response.headers,
    }),
  );
}
