import { NextResponse } from "next/server";
import { routeEmailPasswordProviderRequest } from "./emailPasssword";
import { serverAuth } from "@/server/core/singleton";
import { routeOIDCProviderRequest } from "./OIDCProvider";

/** Used to handle the provider request route */
export async function routeProviderRequest(
  segments: string[],
  method: string,
  body: any,
  cookies: Record<string, string>
): Promise<Response> {
  const providerId = segments[1];

  // Provider: emailPassword
  if (providerId === "emailPassword") {
    return await routeEmailPasswordProviderRequest(segments, method, body);
  }

  // Provider: OIDC
  const oidcProvider = serverAuth.providers.oidc?.[providerId];

  // If no such OIDC provider
  if (!oidcProvider) {
    return new Response("Provider not found", { status: 404 });
  }

  return await routeOIDCProviderRequest(
    segments,
    method,
    body,
    cookies,
    oidcProvider
  );
}
