import { ClientEmailPassword } from "./providers/clientEmailPassword";

/** Wrapper object for client-side auth methods */
export const ClientAuth = {
  // TODO: in future, find a way to dynamically load providers based on authConfig
  emailPassword: ClientEmailPassword,
  // providers: Array.from(authConfig.providers).reduce((acc, provider) => {
  //   if (provider.id === "emailPassword") {
  //     acc.emailPassword = ClientEmailPassword;
  //   }
  //   return acc;
  // }, {} as { emailPassword?: typeof ClientEmailPassword }),
};
