import bcrypt from 'bcrypt';
import * as uuid from 'uuid';
import { User } from '../types/user';
import { DatabaseInterface } from './databaseInterface';


/**
 * THIS IS A DUMMY REPRESENTATION OF A CUSTOM DB
 * 
 * Feel free to use in production if you hate yourself
 * 
 * NOTE: For development purposes, this comes with an already registered user:
 * 
 * `jeremy@topgr.com` with pw `my_genius`
 */
export class DummyDB implements DatabaseInterface {

    /** Table used to store user data */
    private readonly USERS_TABLE: User[] = [
        {
            userId: "31724016-fc90-4ff6-876f-d1cf6cd66976",
            email: "jeremy@topgr.com",
        }
    ];

    /** Stores hashed password for each user */
    private readonly PASSWORD_BY_USER: Map<string, string> = new Map<string, string>([
        ["31724016-fc90-4ff6-876f-d1cf6cd66976", "$2b$10$jaUsbN9Of2OM0YM6i9w7FuDBJtU6BpP6ZrAR7DCtT4jcxUf8oNBvS"]
    ]);

    /** Creates a user given email and password.
     * Password is hashed
     * 
     * If user with the same email already exists, returns null
     */
    public async createUserByEmailPassword(email: string, password: string): Promise<User | null> {
        if (this.USERS_TABLE.some(u => u.email === email)) {
            return null;
        }

        const user: User = {
            userId: uuid.v4(),
            email: email
        };

        this.USERS_TABLE.push(user);

        const hashedPw = await bcrypt.hash(password, 10);
        this.PASSWORD_BY_USER.set(user.userId, hashedPw);

        return user;
    }

    /** Retrieves a user by email if the corresponding hashed password matches */
    public async getUserByEmailPassword(email: string, password: string): Promise<User | null> {
        const user: User | null = this.USERS_TABLE.find(u => u.email === email) || null;

        if (user) {
            const hashedPw = this.PASSWORD_BY_USER.get(user.userId) || null;

            if (hashedPw) {
                const isPwOk = await bcrypt.compare(password, hashedPw);

                if (isPwOk) {
                    return user;
                }
            }
        }

        return null;
    }

    /** Retrieves user data by its id. Returns null if not found */
    public async getUserByUserId(userId: string): Promise<User | null> {
        const user: User | null = this.USERS_TABLE.find(u => u.userId === userId) || null;

        return user;
    }

    /** Lists user data */
    public async listUsers(): Promise<User[]> {
        return Promise.resolve(this.USERS_TABLE);
    }
}