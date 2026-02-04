import { ServerEmailPassword } from "@/server/classes/auth/server/auth/providers/serverEmailPassword";
import { DataOnly } from "@/shared/utils";

/** Type of the result returned by EmailPasswordProvider login method */
export type EmailPasswordProviderLoginResult = DataOnly<
  Awaited<ReturnType<ServerEmailPassword["login"]>>
>;

/** Type of the result returned by EmailPasswordProvider register method */
export type EmailPasswordProviderRegisterResult = DataOnly<
  Awaited<ReturnType<ServerEmailPassword["register"]>>
>;
