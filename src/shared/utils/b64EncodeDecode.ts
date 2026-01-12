/** Encodes a buffer into a base 64 string */
export function base64urlEncode(data: Buffer): string {
  return data
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

/** Decodes a base 64 string into a buffer */
export function base64urlDecode(str: string): Buffer {
  const pad = (4 - (str.length % 4 || 4)) % 4;
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  return Buffer.from(base64, "base64");
}
