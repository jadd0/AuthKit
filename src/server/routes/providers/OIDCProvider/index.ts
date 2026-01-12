import { GeneralOIDC } from "@/server/classes/providers/generalOIDC";
import { routeOIDCAuthorise, routeOIDCCallback } from "./methods";

/** Handle OIDC provider requests */
export async function routeOIDCProviderRequest(
  segments: string[],
  method: string,
  { body, url }: { body: any; url: string },
  cookies: Record<string, string>,
  oidcProvider: GeneralOIDC
): Promise<Response> {
  const action = segments[2]; // e.g. authorize, callback, etc.

  if (action === "authorize" && method === "GET") {
    return await routeOIDCAuthorise(oidcProvider, cookies, { body, url });
  }

  if (action === "callback" && method === "GET") {
    return await routeOIDCCallback(oidcProvider, cookies, url);
  }

  return new Response("Action not found", { status: 404 });
}
