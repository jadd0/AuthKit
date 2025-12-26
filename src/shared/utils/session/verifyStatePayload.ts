import { authConfig } from "@/server/core/singleton";
import { StatePayload } from "@/shared/types";
import { createHmac, timingSafeEqual } from "crypto";

/** Helper used to verify a state payload for OIDC providers */
export function verifyStatePayload(token: string): StatePayload {
  const parts = token.split(".");
  if (parts.length !== 2) {
    throw new Error("Invalid state token format");
  }

  const [dataB64, sigB64] = parts;
  const data = base64urlDecode(dataB64);
  const sig = base64urlDecode(sigB64);

  const expectedSig = createHmac("sha256", authConfig.options.stateSecret)
    .update(data)
    .digest();

  if (sig.length !== expectedSig.length || !timingSafeEqual(sig, expectedSig)) {
    throw new Error("Invalid state token signature");
  }

  const json = data.toString("utf8");
  const payload = JSON.parse(json) as StatePayload;

  return payload;
}
