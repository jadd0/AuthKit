
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
}
