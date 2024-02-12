import bcrypt from 'bcrypt';
import * as uuid from 'uuid';
import { User } from '../types/user';


/**
 * THIS IS A DUMMY REPRESENTATION OF A CUSTOM DB
 * 
 * Feel free to use in production if you hate yourself
 */
export module DummyDB {


    /** Table used to store user data */
    const USERS_TABLE: User[] = [];

    /** Stores hashed password for each user */
    const PASSWORD_BY_USER: Map<string, string> = new Map<string, string>();

    /** Creates a user given email and password.
     * Password is hashed
     */
    export async function createUserByEmailPassword(email: string, password: string): Promise<User> {
        if (USERS_TABLE.some(u => u.email === email)) {
            throw new Error("Email already used");
        }

        const user: User = {
            userId: uuid.v4(),
            email: email
        };

        USERS_TABLE.push(user);

        const hashedPw = await bcrypt.hash(password, 10);
        PASSWORD_BY_USER.set(user.userId, hashedPw);

        return user;
    }

    /** Retrieves a user by email if the corresponding hashed password matches */
    export async function getUserByEmailPassword(email: string, password: string): Promise<User | null> {
        const user: User | null = USERS_TABLE.find(u => u.email === email) || null;

        if (user) {
            const hashedPw = PASSWORD_BY_USER.get(user.userId) || null;

            if (hashedPw) {
                const isPwOk = await bcrypt.compare(password, hashedPw);

                if (isPwOk) {
                    return user;
                }
            }
        }

        return null;
    }

    /** Retrieves user data by its id */
    export async function getUserByUserId(userId: string): Promise<User> {
        const user: User | null = USERS_TABLE.find(u => u.userId === userId) || null;

        if (!user) {
            throw new Error("User not found");
        }

        return user;
    }

    /** Lists user data */
    export async function listUsers(): Promise<User[]> {
        return Promise.resolve(USERS_TABLE);
    }
}