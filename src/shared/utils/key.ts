import { base64Decode } from "./decoder";

/** Function to convert a shared secret and convert to a WebCrypto-ready key to verify HMAC-SHA256 tags produced for a JWT singing input
 * 
 * Using a HMAC (symmetric) key here since it's simpler for most applications than using RSA or ECDSA (asymmetric) keys
 * Additionally, HMAC is generally considered better than RSA for JWT signing due to performance and security considerations, especially when only one trusted backend service will utilise it
 */
export async function importHmacKey(secret: string): Promise<CryptoKey> {
  const enc = new TextEncoder().encode(secret);
  return crypto.subtle.importKey(
    "raw",
    enc,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

/** Function to produce a new ArrayBuffer containing the bytes represented by this view */
function toArrayBuffer(u8: Uint8Array) {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

/** Return type of verifying the JWT */
type DecodeResult = { ok: true; payload: any } | { ok: false };

/** Function used to verify a JWT (HS256) */
export async function verifyJWT(
  token: string,
  secret: string
): Promise<DecodeResult> {
  const parts = token.split(".");
  if (parts.length !== 3) return { ok: false };

  const [headerB64, payloadB64, signatureB64] = parts;

  // Decode JSON from base64url (safe to use Buffer here just for JSON)
  let header: any, payload: any;
  try {
    const headerJson = Buffer.from(
      headerB64.replace(/-/g, "+").replace(/_/g, "/") +
        "===".slice((headerB64.length + 3) % 4),
      "base64"
    ).toString("utf-8");
    const payloadJson = Buffer.from(
      payloadB64.replace(/-/g, "+").replace(/_/g, "/") +
        "===".slice((payloadB64.length + 3) % 4),
      "base64"
    ).toString("utf-8");
    header = JSON.parse(headerJson);
    payload = JSON.parse(payloadJson);
  } catch {
    return { ok: false };
  }

  if (header.alg !== "HS256" || header.typ !== "JWT") return { ok: false };

  // Verify signature over the ASCII headerB64.payloadB64 (not decoded JSON)
  const key = await importHmacKey(secret);
  const data = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = base64Decode(signatureB64);

  const algo: HmacImportParams = { name: "HMAC", hash: "SHA-256" };
  const isValid = await crypto.subtle.verify(
    algo,
    key,
    toArrayBuffer(signature) as ArrayBuffer,
    toArrayBuffer(data) as ArrayBuffer
  );
  if (!isValid) return { ok: false };

  // Check token expiry (if present)
  if (typeof payload.exp === "number") {
    const now = Math.floor(Date.now() / 1000);
    if (now >= payload.exp) return { ok: false };
  }

  return { ok: true, payload };
}
