import { Discovery, StatePayload } from "@/shared/types";
import { signStatePayload, verifyStatePayload } from "@/shared/utils/session";

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

  /** Method used to encode the state and nonce into a cookie */
  encodeStateCookie(state: string, nonce: string, redirectTo?: string): string {
    const payload: StatePayload = {
      state,
      nonce,
      redirectTo,
      providerId: this.id,
    };

    return signStatePayload(payload);
  }

  /** Method used to decode and verify the state cookie */
  decodeStateCookie(token: string) {
    const payload = verifyStatePayload(token);

    if (payload.providerId !== this.id) {
      throw new Error("State token does not belong to this provider");
    }

    return {
      state: payload.state,
      nonce: payload.nonce,
      redirectTo: payload.redirectTo,
    };
  }

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

  /** Method used to exchange the code returned by the OIDC provider for tokens */
  async exchangeCodeForTokens(code: string, codeVerifier: string) {
    // Ensure we have the discovery document
    const discovery = await this.fetchDiscovery();
    const tokenEndpoint = discovery.token_endpoint;

    // Prepare the token exchange request
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: code,
      redirect_uri: this.redirectURI,
      client_id: this.clientId,
      code_verifier: codeVerifier,
    });

    // Make the token exchange request
    const res = await fetch(tokenEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
    });

    if (!res.ok) {
      throw new Error("Failed to exchange code for tokens");
    }

    return res.json() as Promise<{
      access_token: string;
      id_token: string;
      refresh_token?: string;
      expires_in: number;
      token_type: string;
      scope?: string;
    }>;
  }

  /** Method used to validate the returned token fron the OIDC provider */
  async validateIdToken(idToken: string, expectedNonce: string) {
    // Ensure we have the discovery document
    const discovery = await this.fetchDiscovery();
    const jwksURI = discovery.jwks_uri;

    // Fetch the JWKS
    const JWKS = require("jose").createRemoteJWKSet(new URL(jwksURI));

    // Verify the ID token
    const { jwtVerify } = require("jose");

    const { payload } = await jwtVerify(idToken, JWKS, {
      audience: this.clientId,
      issuer: this.issuer,
    });

    // Validate nonce
    if (payload.nonce !== expectedNonce) {
      throw new Error("Invalid nonce in ID token");
    }

    return payload as {
      sub: string;
      iss: string;
      aud: string | string[];
      exp: number;
      iat: number;
      nonce?: string;
      email?: string;
      email_verified?: boolean;
      name?: string;
      picture?: string;
      [key: string]: unknown;
    };
  }

  /** Build the authorisation URL and state cookie for a login attempt */
  async createAuthorisationUrl(redirectTo?: string) {
    const { authorization_endpoint } = await this.fetchDiscovery();

    const codeVerifier = this.generateCodeVerifier();
    const codeChallenge = await this.deriveCodeChallenge(codeVerifier);
    const { state, nonce } = this.generateStateAndNonce();

    const url = new URL(authorization_endpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", this.clientId);
    url.searchParams.set("redirect_uri", this.redirectURI);
    url.searchParams.set("scope", this.scopes.join(" "));
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("state", state);
    url.searchParams.set("nonce", nonce);

    const stateCookieValue = this.encodeStateCookie(state, nonce, redirectTo);

    return {
      authorizationUrl: url.toString(),
      stateCookieValue,
      codeVerifier,
    };
  }

  /** Handle callback: verify state, exchange code, validate ID token */
  async handleCallback(params: {
    code: string;
    stateFromQuery: string;
    stateCookie: string;
    codeVerifier: string;
  }) {
    const { state, nonce, redirectTo } = this.decodeStateCookie(
      params.stateCookie
    );
    if (state !== params.stateFromQuery) {
      throw new Error("Invalid state parameter");
    }

    const tokens = await this.exchangeCodeForTokens(
      params.code,
      params.codeVerifier
    );

    if (!tokens.id_token) {
      throw new Error("No ID token returned from provider");
    }

    const claims = await this.validateIdToken(tokens.id_token, nonce);

    const profile = {
      id: claims.sub,
      email: claims.email,
      emailVerified: claims.email_verified,
      name: claims.name,
      image: claims.picture,
      raw: claims,
    };

    return { tokens, claims, profile, redirectTo };
  }
}
