type LogLevel = "debug" | "info" | "warn" | "error";

/** Custom logger for AuthKit for more professional console logging */
class AuthKitLogger {
  private enabled: boolean;

  constructor() {
    this.enabled =
      process.env.NODE_ENV === "development" ||
      process.env.AUTHKIT_DEBUG === "true";
  }

  debug(message: string, ...args: any[]) {
    if (this.enabled) {
      console.log(`[AuthKit:Debug] ${message}`, ...args);
    }
  }

  info(message: string, ...args: any[]) {
    if (this.enabled) {
      console.log(`[AuthKit:Info] ${message}`, ...args);
    }
  }

  warn(message: string, ...args: any[]) {
    console.warn(`[AuthKit:Warn] ${message}`, ...args);
  }

  error(message: string, ...args: any[]) {
    console.error(`[AuthKit:Error] ${message}`, ...args);
  }
}
