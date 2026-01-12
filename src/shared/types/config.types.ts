import z from "zod";
import { AuthConfigSchema, DatabasePoolConfigSchema } from "../validation";
import { PROVIDERS } from "../constants";

/** Providers enum type used for config */
export type Providers = typeof PROVIDERS[number]

/** Auth config type used for validation */
export type AuthConfig = z.infer<typeof AuthConfigSchema>;

/** Database Pool type */
export type DatabasePoolConfig = z.infer<typeof DatabasePoolConfigSchema>;

/** Database config type (pool and url allowance) */
export type DatabaseConfig = DatabasePoolConfig | string;

export type OIDCProviderConfig = {
  id: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectURI: string;
  scopes: string[];
}