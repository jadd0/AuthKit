import { GeneralOIDC } from "@/server/classes/providers/generalOIDC";
import { auth, authConfig } from "@/server/core/singleton";
import { DatabaseAccountInteractions } from "@/server/db/interfaces/databaseAccountInteractions";
import { DatabaseUserInteractions } from "@/server/db/interfaces/databaseUserInteractions";
import { generateSessionCookie } from "@/shared/utils/session/generateSessionCookie";

/** Handle OIDC callback requests */
export async function routeOIDCCallback(
  provider: GeneralOIDC,
  cookies: Record<string, string>,
  requestUrl: string
): Promise<Response> {
  const url = new URL(requestUrl);
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

    console.log({ newUser });

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
  } else {
    const existingAccount =
      await DatabaseAccountInteractions.getAccountByCompositeKey(
        user.id,
        provider.id
      );

    if (existingAccount) {
      // Update existing account with new tokens
      const updatedAccount =
        await DatabaseAccountInteractions.updateAccountTokens(
          tokens.access_token,
          tokens.refresh_token!,
          tokens.expires_in,
          user.id,
          provider.id
        );

      if (!updatedAccount) {
        return new Response("Failed to update OIDC account", { status: 500 });
      }
    } 
    
    else {
      // Update existing account
      const account = await DatabaseAccountInteractions.createAccount({
        userId: user.id,
        provider: provider.id,
        providerAccountId: profile.id,
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        expiresAt: tokens.expires_in, // TODO: check?
      });

      if (!account) {
        return new Response("Failed to create OIDC account", { status: 500 });
      }
    }
  }

  const session = await auth.sessions.createSession(user);

  if (!session) {
    return new Response("Failed to create session", { status: 500 });
  }

  const DEFAULTIDLETTL = 60 * 60 * 24 * 7; // 7 days in seconds

  const sessionCookie = generateSessionCookie(
    "session",
    session.getSessionToken(),
    authConfig.options.idleTTL ?? DEFAULTIDLETTL
  );

  const headers = new Headers();
  headers.append("Set-Cookie", sessionCookie);

  headers.set("Location", redirectTo ?? "/");
  return new Response(null, { status: 302, headers });
}
