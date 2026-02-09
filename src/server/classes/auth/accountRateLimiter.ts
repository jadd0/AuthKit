interface AccountAttempt {
  failedAttempts: number; // Number of failed attempts in current window
  windowStart: number; // Start of the current rate limit window (timestamp in ms)
  lockedUntil?: number; // Timestamp when account lockout expires (if locked)
  lastAttempt: number; // Timestamp of most recent attempt
}

interface RateLimitResult {
  allowed: boolean;
  remainingAttempts?: number;
  lockedUntil?: Date;
  message?: string;
}

/**
 * Account-based rate limiter for authentication requests
 * Tracks failed login attempts per email address and implements account lockout
 */
export class AccountRateLimiter {
  // START: CREATE
  windowMs: number; // Time window in milliseconds for counting attempts
  maxAttempts: number; // Maximum failed attempts allowed within the time window
  lockoutMs: number; // Duration of account lockout after exceeding max attempts
  skipSuccessfulRequests: boolean; // Whether successful logins reset the counter

  attempts: Map<string, AccountAttempt>; // Map to track attempts per email

  constructor(config: {
    windowMs: number;
    maxAttempts: number;
    lockoutMs: number;
    skipSuccessfulRequests?: boolean;
  }) {
    this.windowMs = config.windowMs;
    this.maxAttempts = config.maxAttempts;
    this.lockoutMs = config.lockoutMs;
    this.skipSuccessfulRequests = config.skipSuccessfulRequests ?? true;
    this.attempts = new Map();

    // Cleanup old entries every 5 minutes
    setInterval(
      () => {
        this.cleanupExpiredEntries();
      },
      5 * 60 * 1000,
    );
  }

  // END: CREATE

  // START: READ

  /**
   * Check if an email address has exceeded the rate limit
   * @param email - Email address to check
   * @returns Result indicating if request is allowed and remaining attempts
   */
  checkRateLimit(email: string): RateLimitResult {
    const normalisedEmail = email.toLowerCase().trim();
    const now = Date.now();
    const attempt = this.attempts.get(normalisedEmail);

    // No previous attempts - allow
    if (!attempt) {
      return {
        allowed: true,
        remainingAttempts: this.maxAttempts,
      };
    }

    // Check if account is currently locked
    if (attempt.lockedUntil && now < attempt.lockedUntil) {
      const lockedUntilDate = new Date(attempt.lockedUntil);
      const remainingSeconds = Math.ceil((attempt.lockedUntil - now) / 1000);

      return {
        allowed: false,
        lockedUntil: lockedUntilDate,
        message: `Account locked for ${remainingSeconds} more seconds due to too many failed login attempts`,
      };
    }

    // Lockout expired - reset
    if (attempt.lockedUntil && now >= attempt.lockedUntil) {
      this.resetRateLimit(normalisedEmail);
      
      return {
        allowed: true,
        remainingAttempts: this.maxAttempts,
      };
    }

    // Check if time window has expired
    if (now - attempt.windowStart > this.windowMs) {
      // Window expired - reset counter
      this.resetRateLimit(normalisedEmail);

      return {
        allowed: true,
        remainingAttempts: this.maxAttempts,
      };
    }

    // Within window - check attempt count
    const remainingAttempts = this.maxAttempts - attempt.failedAttempts;

    // Max attempts exceeded - lock account
    if (remainingAttempts <= 0) {
      attempt.lockedUntil = now + this.lockoutMs;

      return {
        allowed: false,
        lockedUntil: new Date(attempt.lockedUntil),
        message: `Too many failed login attempts. Account locked for ${Math.ceil(this.lockoutMs / 1000)} seconds`,
      };
    }

    return {
      allowed: true,
      remainingAttempts,
    };
  }

  /**
   * Get current attempt status for an email (for debugging/monitoring)
   */
  getAttemptStatus(email: string): AccountAttempt | null {
    const normalisedEmail = email.toLowerCase().trim();
    return this.attempts.get(normalisedEmail) || null;
  }

  // END: READ

  // START: UPDATE

  /**
   * Record a login attempt (failed or successful)
   * @param email - Email address
   * @param successful - Whether the login was successful
   * @returns Result indicating if the attempt was recorded and if account is now locked
   */
  recordAttempt(email: string, successful: boolean): RateLimitResult {
    const normalisedEmail = email.toLowerCase().trim();
    const now = Date.now();

    // If successful and we skip successful requests, reset the limit
    if (successful && this.skipSuccessfulRequests) {
      this.resetRateLimit(normalisedEmail);
      return {
        allowed: true,
        message: "Login successful - rate limit reset",
      };
    }

    // Check rate limit before recording
    const checkResult = this.checkRateLimit(normalisedEmail);

    // If already locked, don't record another attempt
    if (!checkResult.allowed && checkResult.lockedUntil) {
      return checkResult;
    }

    let attempt = this.attempts.get(normalisedEmail);

    // Create new attempt record if this is the first attempt
    if (!attempt) {
      attempt = {
        failedAttempts: successful ? 0 : 1,
        windowStart: now,
        lastAttempt: now,
      };
      this.attempts.set(normalisedEmail, attempt);

      return {
        allowed: true,
        remainingAttempts: this.maxAttempts - (successful ? 0 : 1),
      };
    }

    // Check if window expired
    if (now - attempt.windowStart > this.windowMs) {
      // Reset window
      attempt.windowStart = now;
      attempt.failedAttempts = successful ? 0 : 1;
      attempt.lastAttempt = now;
      attempt.lockedUntil = undefined;

      return {
        allowed: true,
        remainingAttempts: this.maxAttempts - (successful ? 0 : 1),
      };
    }

    // Increment failed attempts counter (only for failed logins)
    if (!successful) {
      attempt.failedAttempts++;
      attempt.lastAttempt = now;

      // Check if max attempts exceeded
      if (attempt.failedAttempts >= this.maxAttempts) {
        attempt.lockedUntil = now + this.lockoutMs;

        return {
          allowed: false,
          lockedUntil: new Date(attempt.lockedUntil),
          message: `Account locked for ${Math.ceil(this.lockoutMs / 1000)} seconds`,
        };
      }

      return {
        allowed: true,
        remainingAttempts: this.maxAttempts - attempt.failedAttempts,
      };
    }

    // Successful login within window (if not skipping successful requests)
    attempt.lastAttempt = now;
    return {
      allowed: true,
      remainingAttempts: this.maxAttempts - attempt.failedAttempts,
    };
  }

  /**
   * Clean up expired entries to prevent memory leaks
   * Called automatically every 5 minutes
   */
  private cleanupExpiredEntries() {
    const now = Date.now();
    const toDelete: string[] = [];

    for (const [email, attempt] of this.attempts.entries()) {
      // Delete if:
      // 1. Window expired and no lockout, OR
      // 2. Lockout expired and window expired
      const windowExpired = now - attempt.windowStart > this.windowMs;
      const lockoutExpired = !attempt.lockedUntil || now > attempt.lockedUntil;

      if (windowExpired && lockoutExpired) {
        toDelete.push(email);
      }
    }

    toDelete.forEach((email) => this.attempts.delete(email));

    if (toDelete.length > 0) {
      console.log(
        `[AccountRateLimiter] Cleaned up ${toDelete.length} expired entries`,
      );
    }
  }

  // END: UPDATE

  // START: DELETE

  /**
   * Reset rate limit for an email (e.g., after successful login or manual unlock)
   * @param email - Email address to reset
   */
  resetRateLimit(email: string): void {
    const normalisedEmail = email.toLowerCase().trim();
    this.attempts.delete(normalisedEmail);
  }

  /**
   * Clear all rate limit records (for testing or maintenance)
   */
  clearAllRateLimits(): void {
    this.attempts.clear();
  }

  /**
   * Manually unlock an account (admin function)
   * @param email - Email address to unlock
   */
  unlockAccount(email: string): boolean {
    const normalisedEmail = email.toLowerCase().trim();
    const attempt = this.attempts.get(normalisedEmail);

    if (!attempt) {
      return false; // No record found
    }

    // Remove the entry entirely
    this.attempts.delete(normalisedEmail);
    return true;
  }

  /**
   * Get statistics about current rate limiting state (for monitoring)
   */
  getStats(): {
    totalTrackedAccounts: number;
    lockedAccounts: number;
    accountsNearLimit: number;
  } {
    const now = Date.now();
    let lockedAccounts = 0;
    let accountsNearLimit = 0;

    for (const attempt of this.attempts.values()) {
      if (attempt.lockedUntil && now < attempt.lockedUntil) {
        lockedAccounts++;
      } else if (attempt.failedAttempts >= this.maxAttempts - 1) {
        accountsNearLimit++;
      }
    }

    return {
      totalTrackedAccounts: this.attempts.size,
      lockedAccounts,
      accountsNearLimit,
    };
  }

  // END: DELETE
}
