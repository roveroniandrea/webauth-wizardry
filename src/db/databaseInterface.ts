import { OpenIDUser, User } from '../types/user';

/** Represents a generic database implementation */
export interface DatabaseInterface {
    /** 
     * Creates a user given email and password.
     * Password is hashed
     * 
     * NOTE: For now, this does not allow to merge already existing users registered in other ways, for example with openID providers
     */
    createPasswordForUser(userId: string, password: string): Promise<void>;

    /** Retrieves a user by email if the corresponding hashed password matches */
    getUserByEmailPassword(email: string, password: string): Promise<User | null>;

    /** Retrieves user data by its id. Returns null if not found */
    getUserByUserId(userId: string): Promise<User | null>;

    /** Retrieves a user just for his email, looking in the primary table */
    getUserByEmail(email: string): Promise<User | null>;

    /** Creates a user in the primary table */
    createUserByEmail(email: string): Promise<User>;

    /** Retrieves a user from an openID provider, if it exists */
    getOpenIdUser(providerName: string, sub: string): Promise<OpenIDUser | null>;

    /** Retrieves a user from an openID provider */
    createOpenIdUser(openIdUser: OpenIDUser): Promise<void>;

    /** Cheks is a password exists given a userId */
    isPasswordSetForUserId(userId: string): Promise<boolean>;
}