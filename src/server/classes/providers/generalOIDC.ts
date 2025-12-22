import { Discovery } from "@/shared/types";

/**
 * @class GeneralOIDC
 * @description This class provides a general OIDC provider creation, for ease of creating custom providers
 */
export class GeneralOIDC {
  id: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectURI: string;
  scopes: string[];
  jwksURI?: string;
  discovery?: Discovery;

  constructor(
    id: string,
    issuer: string,
    clientId: string,
    clientSecret: string,
    redirectURI: string,
    scopes: string[]
  ) {
    this.id = id;
    this.issuer = issuer;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.redirectURI = redirectURI;
    this.scopes = scopes;
  }

  /** Method used to generate a 64 random character long code verifier */
  generateCodeVerifier(): string {
    // Generate 48 random bytes (384 bits of entropy)
    const randomBytes =
      typeof crypto !== "undefined" && "getRandomValues" in crypto
        ? crypto.getRandomValues(new Uint8Array(48))
        : require("crypto").randomBytes(48);

    // Convert to base64url string
    let base64 = Buffer.from(randomBytes).toString("base64");
    const base64url = base64
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");

    // Ensure length is exactly 64 chars
    if (base64url.length >= 64) {
      return base64url.slice(0, 64);
    }

    // If shorter (rare), pad with extra random chars from the same charset
    const charset =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let result = base64url;
    while (result.length < 64) {
      const idx =
        typeof crypto !== "undefined" && "getRandomValues" in crypto
          ? crypto.getRandomValues(new Uint8Array(1))[0] % charset.length
          : require("crypto").randomBytes(1)[0] % charset.length;
      result += charset[idx];
    }

    return result;
  }

  /** Method used to change the verifier, high entropy string, into a code challenge to send to the authorisation endpoint */
  async deriveCodeChallenge(verifier: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);

    let hash: ArrayBuffer;

    // Compute the SHA-256 of the hash

    // Web Crypto (browser / Edge runtime)
    if (typeof crypto !== "undefined" && "subtle" in crypto) {
      hash = await crypto.subtle.digest("SHA-256", data);
    }

    // Node.js crypto
    else {
      const nodeCrypto = require("crypto") as typeof import("crypto");
      const digest = nodeCrypto
        .createHash("sha256")
        .update(verifier, "utf8")
        .digest();
      hash = digest.buffer.slice(
        digest.byteOffset,
        digest.byteOffset + digest.byteLength
      );
    }

    // Formatting

    const hashBytes = new Uint8Array(hash);
    let base64 = Buffer.from(hashBytes).toString("base64");

    const base64url = base64
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");

    return base64url;
  }

  /** Method used to generate a state and nonce value */
  generateStateAndNonce(): { state: string; nonce: string } {
    // Random character set
    const charset =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    // Generate a crypto-random string
    const randomString = (length: number): string => {
      const bytes =
        typeof crypto !== "undefined" && "getRandomValues" in crypto
          ? crypto.getRandomValues(new Uint8Array(length))
          : require("crypto").randomBytes(length);

      let out = "";
      for (let i = 0; i < bytes.length; i++) {
        out += charset[bytes[i] % charset.length];
      }
      return out;
    };

    // Sizes are flexible; 32–64 chars is common and gives strong entropy. Recommended is 43-128.
    const state = randomString(64);
    const nonce = randomString(64);

    return { state, nonce };
  }

  encodeStateCookie(state: string, nonce: string) {}

  decodeStateCookie(state: string, nonce: string) {}

  /** A method used to fetch OIDC discovery document */
  async fetchDiscovery(): Promise<Discovery> {
    // If there is already a cached discovery document
    if (this.discovery) return this.discovery;

    // Fetch discovery document from the OIDC provider
    const res = await fetch(`${this.issuer}/.well-known/openid-configuration`);
    if (!res.ok) throw new Error("Failed to fetch OIDC discovery document");

    const json = await res.json();

    this.discovery = json;
    this.jwksURI = json.jwks_uri;

    return json;
  }

  exchangeCodeForTokens(tokenEndpoint: string, codeVerifier: string) {}

  validateIdToken(idToken: string, jwksURI: string) {}
}
