import { GeneralOIDC } from "./generalOIDC";

export class GoogleProvider {
  clientId: string;
  clientSecret: string;
  redirectURI: string;
  scopes: string[];
  generalOIDC: GeneralOIDC;

  constructor(
    clientId: string,
    clientSecret: string,
    redirectURI: string,
    scopes: string[]
  ) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.redirectURI = redirectURI;
    this.scopes = scopes;

    this.generalOIDC = new GeneralOIDC(
      "google",
      "https://accounts.google.com",
      clientId,
      clientSecret,
      redirectURI,
      scopes
    );
  }
}
