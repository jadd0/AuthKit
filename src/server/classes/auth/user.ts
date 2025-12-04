/**
 * @class User
 * @description Represents a user in the authentication system for server-side operations.
 * @property {string} id - The unique identifier for the user.
 * @property {string} email - The email address of the user.
 * @property {string | undefined} name - The name of the user (optional).
 * @property {string[] | undefined} roles - The roles assigned to the user (optional).
 * @property {string | undefined} picture - The URL of the user's profile picture (optional).
 */
export class User {
  id: string;
  email: string;
  name: string | undefined;
  roles: string[] | undefined;
  picture: string | undefined;

  constructor(
    id: string,
    email: string,
    name?: string,
    roles?: string[],
    picture?: string
  ) {
    this.id = id;
    this.email = email;
    this.name = name;
    this.roles = roles;
    this.picture = picture;
  }

  /** Used to retrieve the user ID */
  getId(): string {
    return this.id;
  }

  /** Used to retrieve the user's email */
  getEmail(): string {
    return this.email;
  }

  /** Used to retrieve the user's name */
  getName(): string | undefined {
    return this.name;
  }

  /** Used to retrieve the roles of the user */
  getRoles(): string[] | undefined {
    return this.roles;
  }

  /** Used to retrieve the user's profile picture URL */
  getPicture(): string | undefined {
    return this.picture;
  }
}
