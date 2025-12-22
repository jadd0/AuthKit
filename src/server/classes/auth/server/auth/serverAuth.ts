import { authConfig } from "@/server/core/singleton";
import { ServerEmailPassword } from "./providers/serverEmailPassword";

export class ServerAuth {
  providers: {
    emailPassword?: ServerEmailPassword;
    // google?: any;
  } = {};

  constructor() {
    for (const provider of authConfig.providers) {
      if (provider.id === "emailPassword") {
        this.providers.emailPassword = new ServerEmailPassword();
      }
    }
  }
}
