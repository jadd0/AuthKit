import crypto from "crypto";
import { authConfig } from "@/server/core/singleton";

export function generateCsrfToken(sessionToken: string): string {
  const secret = authConfig.options.stateSecret;
  return crypto
    .createHmac("sha256", secret)
    .update(sessionToken)
    .digest("hex");
}
