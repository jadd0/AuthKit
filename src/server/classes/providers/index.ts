/**
 * @module Providers
 * @description This module exports various authentication providers.
 */

import { EmailPasswordProvider } from "./emailPassword";

const emailPasswordProvider = new EmailPasswordProvider();

export { emailPasswordProvider as emailPasswordProviderExport };
