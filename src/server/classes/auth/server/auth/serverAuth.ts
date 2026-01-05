import { authConfig } from "@/server/core/singleton";
import { ServerEmailPassword } from "./providers/serverEmailPassword";
import { GeneralOIDC } from "@/server/classes/providers/generalOIDC";
import { PROVIDERS } from "@/shared/constants";

export class ServerAuth {
  providers: {
    emailPassword?: ServerEmailPassword;
    oidc?: Record<string, GeneralOIDC>;
  } = {};

  constructor() {
    for (const provider of authConfig.providers) {
      // Email/password provider
      if (provider.id === "emailPassword") {
        this.providers.emailPassword = new ServerEmailPassword();
      }

      // Google OIDC provider (minimal config)
      else if (provider.type === "oidc" && provider.id === "google") {
        this.providers.oidc = this.providers.oidc || {};
        this.providers.oidc["google"] = new GeneralOIDC(
          "google",
          provider.issuer ?? "https://accounts.google.com",
          provider.clientId,
          provider.clientSecret,
          provider.redirectURI ?? process.env.GOOGLE_REDIRECT_URI!,
          provider.scopes ?? ["openid", "email", "profile"]
        );
      }

      // Generic/custom OIDC providers
      // TODO: check ! on these
      else if (provider.type === "oidc" && provider.id !== "google") {
        this.providers.oidc = this.providers.oidc || {};
        this.providers.oidc[provider.id] = new GeneralOIDC(
          provider.id,
          provider.issuer!, 
          provider.clientId,
          provider.clientSecret,
          provider.redirectURI!, 
          provider.scopes! 
        );
      }
    }
  }
}
