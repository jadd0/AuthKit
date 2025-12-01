import { User } from "@/db/schemas";
import { DatabaseSessionInteractions } from "@/db/interfaces/databaseSessionInteractions";
import { authConfig } from "@/core/singleton";

/** Session class constructor interface */
interface SessionConstructor {
  id: string; // Session ID correlates 1:1 with DB Session ID
  user: User;
  createdAt: Date;
  sessionToken: string;
  lastRetrivedTime?: Date;
  lastActivityTime?: Date;
}

/**
 * @class Session
 * @description Represents a blueprint for an object encapsulating user sessions in the authentication system.
 * @property {User | null} user - The authenticated user associated with the session, or null if unauthenticated.
 * @property {Date} authenticationTime - The timestamp when the session was created or last authenticated.
 */
export class Session {
  // START: CREATE

  id: string;
  user: User;
  sessionToken: string;
  authenticationTime: Date = new Date();
  lastRetrievedTime: Date;
  lastActivityTime: Date;
  createdAt: Date;

  // Optional values given for server cold start appension of Sessions to the server map
  constructor(config: SessionConstructor) {
    this.id = config.id;
    this.user = config.user || null;
    this.sessionToken = config.sessionToken;
    this.createdAt = config.createdAt;
    this.lastRetrievedTime = config.lastRetrivedTime || new Date();
    this.lastActivityTime = config.lastActivityTime || new Date();
  }

  // END: CREATE

  // START: READ

  /** Used to retrieve the authentication state of a user */
  getIsAuthenticated(): boolean {
    return this.user !== null;

    // TODO: implement proper auth logic here
  }

  /** Used to retrieve the user */
  getUser(): User | null {
    return this.user;
  }

  /** Used to retrieve the authentication time (when the session was created or last authenticated) */
  getAuthenticationTime(): Date {
    // TODO: chagne null to whatever
    return this.authenticationTime;
  }

  /** Used to retrieve the last instance of authentication for the current session */
  getLastRetrievedTime(): Date {
    return this.lastRetrievedTime;
  }

  /** Used to retrieve the last instance of activity for the current user */
  getLastActivityTime(): Date {
    return this.lastActivityTime;
  }

  /** Used to retrieve the date time that the session was created*/
  getCreatedAt(): Date {
    return this.createdAt;
  }

  /** Used to retrieve the idle expiry date for the session */
  getSessionIdleExpiry(): Date | null {
    const idleTTL = authConfig.options.idleTTL;

    // If the developer has not set an idleTTL then return null as there is no expiry
    if (!idleTTL) return null;

    // Returning the idle expiry date as the created at time in ms + idleTTL, from config, in ms - producing the expiry
    return new Date(this.getCreatedAt().getTime() + idleTTL * 1000);
  }

  /** Used to retrieve the absolute expiry date for the session */
  getSessionAbsoluteExpiry(): Date | null {
    const absoluteTTL = authConfig.options.absoluteTTL;

    // If the developer has not set an absoluteTTL then return null as there is no expiry
    if (!absoluteTTL) return null;

    // Returning the idle expiry date as the created at time in ms + absoluteTTL, from config, in ms - producing the expiry
    return new Date(this.getCreatedAt().getTime() + absoluteTTL * 1000);
  }

  /** Used to retrieve the session token */
  getSessionToken(): string {
    return this.sessionToken;
  }

  // END: READ

  // START: UPDATE

  /** Used to rotate session */
  rotateSession(): Session {
    // TODO: implement
    return this;
  }

  /** Used to update the last time the user interacted with the system */
  async updateLastActivityTime(): Promise<Session> {
    // Creates a timestamp of now
    const currentTimestamp = new Date();

    // Update DB Sessions table with new timestamp
    const dbResult =
      await DatabaseSessionInteractions.updateLastActivityTimeById(
        this.id,
        currentTimestamp
      );

    // DB error occured
    if (!dbResult) {
      throw new Error(
        `An error has occured whilst attempting to update the last time the User with ID ${this.user.id} interacted with the Session with ID ${this.id}`
      );
    }

    // Update this object
    this.lastActivityTime = currentTimestamp;

    // Return this object
    return this;
  }

  // END: UPDATE

  // START: DELETE
  // END: DELETE
}


