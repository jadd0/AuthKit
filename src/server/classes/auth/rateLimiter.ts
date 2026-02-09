import { th } from "zod/v4/locales";

/** Class to create a rate limiter for authentication requests */
export class RateLimiter {
  // START: CREATE:
  windowMs: number; // Time window in milliseconds
  maxRequests: number; // Maximum number of requests allowed within the time window
  skipSuccessfulRequests: boolean; // Whether to skip counting successful requests towards the rate limit

  requests: Map<string, number[]>; // Map to track requests per identifier {IP, [timestamps in ms]}

  constructor(
    windowMs: number,
    maxRequests: number,
    skipSuccessfulRequests: boolean,
  ) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
    this.skipSuccessfulRequests = skipSuccessfulRequests;
    this.requests = new Map();
  }

  // END: CREATE

  // START: READ

  /** Method to check if an IP has surpassed the rate limit */
  checkRateLimit(ip: string): boolean {
    const requestInfo = this.requests.get(ip);

    // No previous requests from this IP, allow the request
    if (!requestInfo) {
      return true;
    }

    // Filter out timestamps that are outside the time window
    this.deleteOldRequests(ip);

    // Check if the number of requests in the time window exceeds the maximum allowed
    const updatedRequestInfo = this.requests.get(ip);

    // Rate limit exceeded
    if (updatedRequestInfo && updatedRequestInfo.length >= this.maxRequests) {
      return false;
    }

    // Request allowed
    return true;
  }

  // END: READ

  // START: UPDATE

  /** Method to record a request for an IP and return if limitable or not */
  recordRequest(ip: string, successful: boolean): boolean {
    // Clean up old requests before recording the new one
    this.deleteOldRequests(ip);

    const currentTime = Date.now();
    let requestInfo = this.requests.get(ip);

    // If configured to skip successful requests and this request was successful, do not record it
    if (this.skipSuccessfulRequests && successful) {
      return true;
    }

    // Create new request info if this is the first request from this IP
    if (!requestInfo) {
      requestInfo = [];
    }

    // First, check if rate is limitable
    if (requestInfo.length > this.maxRequests) {
      return false;
    }

    // Record the request timestamp
    requestInfo.push(currentTime);

    // Record the request
    this.requests.set(ip, requestInfo);

    // Check again if rate is limitable
    if (requestInfo.length > this.maxRequests) {
      return false;
    }

    return true;
  }

  /** Method to delete old requests that are outside the time window */
  deleteOldRequests(ip: string) {
    const currentTime = Date.now();
    const requestInfo = this.requests.get(ip);

    if (!requestInfo) {
      return;
    }

    // Filter out timestamps that are outside the time window
    const updatedRequestInfo = requestInfo.filter(
      (timestamp) => currentTime - timestamp <= this.windowMs,
    );

    if (updatedRequestInfo.length > 0) {
      this.requests.set(ip, updatedRequestInfo);
    } else {
      this.requests.delete(ip);
    }
  }

  // END: UPDATE

  // START: DELETE

  /** Method to reset the rate limit for an IP (e.g., after a successful login) */
  resetRateLimit(ip: string) {
    this.requests.delete(ip);
  }

  /** Method to clear all rate limit records (e.g., for testing or maintenance) */
  clearAllRateLimits() {
    this.requests.clear();
  }

  /** Method to delete old requests for all IPs (can be called periodically) */
  deleteOldRequestsForAllIPs() {
    // Iterate through all IPs and delete old requests
    for (const ip of this.requests.keys()) {
      this.deleteOldRequests(ip);
    }
  }

  // END: DELETE
}
