import { Session } from "@/server/classes/auth/session";

export type Discovery = {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
};

/** Type describing a OIDC provider state payload */
export interface StatePayload {
  state: string;
  nonce: string;
  redirectTo?: string;
  providerId: string;
}
