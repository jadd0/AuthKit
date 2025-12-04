import { DatabaseUserInteractions } from "@/server/db/interfaces/databaseUserInteractions";
import { Sessions } from "./sessions";
import { User } from "./user";
import { PROVIDERS } from "@/shared/constants";
import { DatabaseSessionInteractions } from "@/server/db/interfaces/databaseSessionInteractions";
/**
 * Main parent Auth class
 * @class Auth
 * @description This class serves as the main entry point for authentication functionalities. This will be extended by specific implementations for server and client environments.
 *
 */
export class Auth {
  // START: CREATE

  sessions: Sessions;
  providers: (typeof PROVIDERS)[];
  callbacks: any;
  idleTTL: number;
  absoluteTTL: number;

  constructor(
    providers: any[],
    callbacks: any,
    idleTTL: number,
    absoluteTTL: number
  ) {
    this.providers = providers;
    this.callbacks = callbacks;
    this.sessions = new Sessions();
    (this.idleTTL = idleTTL), (this.absoluteTTL = absoluteTTL);

    this.retrieveDatabaseSessions();
  }

  /** Used on runtime initialisation to retrieve any sessions inside the database */
  private async retrieveDatabaseSessions() {
    // Attempt to delete all expired database Sessions for storage
    try {
      await DatabaseSessionInteractions.deleteExpiredSessions();
    } catch (error) {
      throw new Error(
        "An error occurred whilst attemtping to delete all expired database authentication Sessions."
      );
    }

    // Attempt to retrieve all active database Sessions to append to the Sessions instance
    let sessions;
    try {
      sessions = await DatabaseSessionInteractions.getAllSessions();
      console.log("Retrieved sessions from database:", sessions);
    } catch (error) {
      throw new Error(
        "An error occurred whilst attempting to retrieve all active database authentication Sessions."
      );
    }
    
    await this.sessions.appendDatabaseSessions(sessions);
  }

  async createSession(userId: string) {
    const user = await DatabaseUserInteractions.getUserById(userId);

    if (!user) {
      throw new Error(
        "There has been an issue trying to create a session for the user with the ID: " +
          userId
      );
    }

    const session = await this.sessions.createSession(user);
  }

  

  // END: CREATE

  // START: READ

  // END: READ

  // START: UPDATE
  // END: UPDATE

  // START: DELETE
  // END: DELETE

  private retrieveUserByIdentification(
    identificationType: string,
    identificationValue: string
  ): User | null {
    return null;
  }

  hello() {
    return new Response("Hello from Auth class handler!");
  }
}
