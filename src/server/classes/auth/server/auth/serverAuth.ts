import { authConfig } from "@/server/core/singleton";
import { ServerEmailPassword } from "./providers/serverEmailPassword";
import { GeneralOIDC } from "@/server/classes/providers/generalOIDC";

export class ServerAuth {
  providers: {
    emailPassword?: ServerEmailPassword;
    oidc?: Record<string, GeneralOIDC>;
  } = {};

  constructor() {
    for (const provider of authConfig.providers) {
      if (provider.id === "emailPassword") {
        this.providers.emailPassword = new ServerEmailPassword();
      }

      if (provider.type == "oidc") {
        this.providers.oidc![provider.id] = new GeneralOIDC(
          provider.id,
          provider.issuer,
          provider.clientId,
          provider.clientSecret,
          provider.redirectURI,
          provider.scopes
        );
      }
    }
  }
}
