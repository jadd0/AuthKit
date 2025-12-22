import { Session } from "@/server/classes/auth/session";

// TODO: type properly
/** Authorisation type to validate user and return defined data about them */
export type Authorise = (
  // A context object to be passed in (eg: requst, env...)
  ctx: unknown,
  // User supplied credentials (eg: form data)
  credentials: unknown
) => Promise<Session>;

export type Discovery = {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
};
