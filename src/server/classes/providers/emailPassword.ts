import { DatabaseAccountInteractions } from "@/server/db/interfaces/databaseAccountInteractions";
import { DatabaseUserInteractions } from "@/server/db/interfaces/databaseUserInteractions";
import { NewUser, User } from "@/shared/schemas";
import { authConfig } from "@/server/core/singleton";
import * as bcrypt from "bcrypt";

/**
 * @class EmailPasswordProvider
 * @description This class provides email and password authentication functionalities.
 */
export class EmailPasswordProvider {
  /** Used to log a User when provided with an email and password */
  async login(email: string, password: string): Promise<User | null> {
    // Attempt to retrieve a User with the provided email
    const userWithEmail = await DatabaseUserInteractions.getUserByEmail(email);

    // No user exists with such email
    if (!userWithEmail) {
      return null;
    }

    // Attempt to retrieve an Account with the retrieved User ID
    const userAccount =
      await DatabaseAccountInteractions.getAccountByCompositeKey(
        userWithEmail.id,
        "emailPassword",
      );

    // No Account exists for email-password provider with the given User ID, or the given Account has no password
    if (!userAccount || !userAccount.password) {
      return null;
    }

    // Compare the provided password with the stored password hash
    const isPasswordCorrect = await bcrypt.compare(
      password,
      userAccount.password,
    );

    // Incorrect password
    if (!isPasswordCorrect) {
      return null;
    }

    return userWithEmail;
  }

  // TODO: make this into a transaction ? not desperate
  /** Used to register a new user for email-password authentication */
  async register(config: NewUser, password: string): Promise<User> {
    // Attempt to retrieve a user with the provided email before anything else
    const userResult = await DatabaseUserInteractions.getUserByEmail(
      config.email,
    );

    // Hash the provided password
    password = await bcrypt.hash(
      password,
      authConfig.providers.find((p) => p.type === "credentials")!
        .saltingRounds!,
    );

    // No given user, therefore no account, or perhaps error.
    if (!userResult) {
      // Attempt to create a new User with the given details
      const newUserResult = await DatabaseUserInteractions.createUser(config);

      // DB error whilst trying to append User to Users table
      if (!newUserResult) {
        throw new Error(
          `An error occurred whilst trying to append the User with email ${config.email} to the Users table. User register failed.`,
        );
      }

      // Attempt to create an email-password Account for the new User
      const newAccountResult = await DatabaseAccountInteractions.createAccount({
        userId: newUserResult.id,
        provider: "emailPassword",
        password,
      });

      // DB error occurred whilst trying to append Account
      if (!newAccountResult) {
        // Delete the User from the Users table as no account has been created
        await DatabaseUserInteractions.deleteUser(newUserResult.id);

        throw new Error(
          `An error occurred whilst trying to append the Account with email ${config.email} to the Account table. User register failed.`,
        );
      }

      return newUserResult;
    }

    // User account exists, try to create a email-password account

    // Attempt to create an email-password Account for the existing
    const newAccountResult = await DatabaseAccountInteractions.createAccount({
      userId: userResult.id,
      provider: "emailPassword",
      password,
    });

    // DB error occurred whilst trying to append the Account
    if (!newAccountResult) {
      throw new Error(
        `An error occurred whilst trying to append the Account with email ${config.email} to the Account table. Email-password register failed.`,
      );
    }

    return userResult;
  }
}
