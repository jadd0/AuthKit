import { SESSION_TOKEN_LENGTH } from "@/shared/constants";
import crypto from 'crypto';

/** Function used to create a random session token, secure to 256 bits */
export function generateSessionToken() {
  // Generates a 64 hex character long string, which == 256 bits
  return crypto.randomBytes(SESSION_TOKEN_LENGTH).toString("hex") 
}