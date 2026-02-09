import crypto from "crypto";
import { authConfig } from "@/server/core/singleton";

export interface CSRFTokenPayload {
  sessionToken: string;
  timestamp: number;
  nonce: string;
  actionHash?: string; // For operation-specific tokens
}

/** Function used to generate a secure CSRF token */
export function generateCsrfToken(
  sessionToken: string,
  action?: string,
): string {
  const secret = authConfig.options.CSRFSecret;

  // No given secret to sign the CSRF token with
  if (!secret) {
    throw new Error("CSRF secret is not configured.");
  }

  const nonce = crypto.randomBytes(16).toString("hex");
  const timestamp = Date.now();

  const payload: CSRFTokenPayload = {
    sessionToken,
    timestamp,
    nonce,
    actionHash: action
      ? crypto.createHash("sha256").update(action).digest("hex")
      : undefined,
  };

  const payloadSignature = JSON.stringify(payload);
  const signature = crypto
    .createHmac("sha256", secret)
    .update(payloadSignature)
    .digest("hex");

  // Token format: base64(payload).signature
  return `${Buffer.from(payloadSignature).toString("base64")}.${signature}`;
}
