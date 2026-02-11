"use client";

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

/** Main hook exports */
export * from "./hooks/";
