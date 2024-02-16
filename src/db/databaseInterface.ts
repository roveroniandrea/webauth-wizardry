import { User } from '../types/user';

/** Represents a generic database implementation */
export interface DatabaseInterface {

    /** 
     * Creates a user given email and password.
     * Password is hashed
     */
    createUserByEmailPassword(email: string, password: string): Promise<User>;

    /** Retrieves a user by email if the corresponding hashed password matches */
    getUserByEmailPassword(email: string, password: string): Promise<User | null>;

    /** Retrieves user data by its id */
    getUserByUserId(userId: string): Promise<User>;
}