import { authConfig } from "@/server/core/singleton";
import { StatePayload } from "@/shared/types";
import { createHmac } from "crypto";

/** Helper used to encode an OIDC provider state payload */
export function signStatePayload(payload: StatePayload): string {
  const json = JSON.stringify(payload);
  const data = Buffer.from(json, "utf8");

  // Create signature
  const sig = createHmac("sha256", authConfig.options.stateSecret)
    .update(data)
    .digest();

  // Base64url encode both
  const dataB64 = base64urlEncode(data);
  const sigB64 = base64urlEncode(sig);

  // token format: data.sig
  return `${dataB64}.${sigB64}`;
}
