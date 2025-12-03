/**
 * @module AuthKit/Client
 * @description Client-side authentication module for AuthKit.
 * Main AuthKit client exports.
 */

import { ClientSession } from "./auth/clientSession";
import { ClientAuth } from "./auth/clientAuth";

/** Main class exports */
export { ClientSession as session };
export { ClientAuth as auth };
 
// TODO: this causes a waterfall when auth not init, find a way to check if auth is init. maybe a /health endpoint?
/** Helper to get the current authenticated user */

export function hello() {
  console.log("Hello from AuthKit Client!");
}

/** Main hook exports */
export * from "./hooks/";
