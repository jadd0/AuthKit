import { GeneralOIDC } from "@/server/classes/providers/generalOIDC";
import { auth, authConfig } from "@/server/core/singleton";
import { DatabaseAccountInteractions } from "@/server/db/interfaces/databaseAccountInteractions";
import { DatabaseUserInteractions } from "@/server/db/interfaces/databaseUserInteractions";
import { generateSessionCookie } from "@/shared/utils/session/generateSessionCookie";

/** Handle OIDC callback requests */
export async function routeOIDCCallback(
  provider: GeneralOIDC,
  cookies: Record<string, string>,
  body: any
): Promise<Response> {
  const url = new URL(body.url); 
  const code = url.searchParams.get("code");
  const stateFromQuery = url.searchParams.get("state");

  if (!code || !stateFromQuery) {
    return new Response("Missing code or state", { status: 400 });
  }

  const stateCookie = cookies["authkit_state"];
  const codeVerifier = cookies["authkit_verifier"];

  if (!stateCookie || !codeVerifier) {
    return new Response("Missing OIDC state or verifier", { status: 400 });
  }

  const { tokens, profile, redirectTo } = await provider.handleCallback({
    code,
    stateFromQuery,
    stateCookie,
    codeVerifier,
  });

  if (!profile || !profile.id) {
    return new Response("Failed to retrieve user profile", { status: 400 });
  }

  // Now create/find user and authenticate

  // 1) find or create user in DB
  // 2) link accounts table
  // 3) create session and set your normal session cookie

  let user = await DatabaseUserInteractions.getUserByEmail(profile.email!);

  // Create user if not exists
  if (!user) {
    const newUser = await DatabaseUserInteractions.createUser({
      email: profile.email!,
      emailVerified: new Date(), // TODO: use actual email verification status if available
      username: profile.email!.split("@")[0],
      name: profile.name || "",
      image: profile.image || "",
      roles: ["user"],
    });

    if (!newUser) {
      return new Response("Failed to create user", { status: 500 });
    }

    // Link OIDC account
    const linkedAccount = await DatabaseAccountInteractions.createAccount({
      userId: newUser.id,
      provider: provider.id,
      providerAccountId: profile.id,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt: tokens.expires_in, // TODO: check?
    });

    if (!linkedAccount) {
      return new Response("Failed to link OIDC account", { status: 500 });
    }

    user = newUser;
  }

  const session = await auth.sessions.createSession(user.id);

  if (!session) {
    return new Response("Failed to create session", { status: 500 });
  }

  const DEFAULTIDLETTL = 60 * 60 * 24 * 7; // 7 days in seconds

  const sessionCookie = generateSessionCookie(
    session.id,
    session.getSessionToken(),
    authConfig.options.idleTTL ?? DEFAULTIDLETTL
  );

  const headers = new Headers();
  headers.append("Set-Cookie", sessionCookie);

  headers.set("Location", redirectTo ?? "/");
  return new Response(null, { status: 302, headers });
}
