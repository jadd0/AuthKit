import { GeneralOIDC } from "@/server/classes/providers/generalOIDC";

/** Handle OIDC authorise requests */
export async function routeOIDCAuthorise(
  provider: GeneralOIDC,
  cookies: Record<string, string>,
  { body, url }: { body: any; url: string }
): Promise<Response> {
  const redirectTo = body?.redirectTo ?? undefined;

  const { authorizationUrl, stateCookieValue, codeVerifier } =
    await provider.createAuthorisationUrl(redirectTo);

  // TODO: store codeVerifier on server side
  // simplest: another signed cookie tied to state
  const headers = new Headers();
  headers.append(
    "Set-Cookie",
    `authkit_state=${stateCookieValue}; Path=/; HttpOnly; Secure; SameSite=Lax`
  );
  headers.append(
    "Set-Cookie",
    `authkit_verifier=${codeVerifier}; Path=/; HttpOnly; Secure; SameSite=Lax`
  );

  headers.set("Location", authorizationUrl);
  return new Response(null, { status: 302, headers });
}
