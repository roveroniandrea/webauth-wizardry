import bcrypt from 'bcrypt';
import * as uuid from 'uuid';
import { OpenIDUser, User } from '../types/user';
import { DatabaseInterface } from './databaseInterface';


/**
 * THIS IS A DUMMY REPRESENTATION OF A CUSTOM DB
 * 
 * Feel free to use in production if you hate yourself
 * 
 * NOTE: For development purposes, this comes with an already registered user:
 * 
 * `jeremy@topgr.com` with pw `my_genius`
 * 
 * 
 * ## Some infos about the fake "tables":
 * - `USERS_TABLE` is like the main table, consisting in a PK `userId` and all the possible user infos, like email
 * - `PASSWORD_BY_USER` is a table for email/pw authentication. It consists of a FK `userId` and other data, like encrypted password
 * - `OPENID_USERS` is a table for openId authentication. It consists of a FK `userId` and other data, like encrypted password
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


    private readonly OPENID_USERS: OpenIDUser[] = [];

    /** Creates a user given email and password.
     * Password is hashed
     * 
     * If user with the same email already exists, returns null
     * TODO: MAybe refactor like openId user creation, to create only on the password table and behave like a FK constraint
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

    public async getUserByEmail(email: string): Promise<User | null> {
        const user: User | null = this.USERS_TABLE.find(u => u.email === email) || null;

        return user;
    }

    public async createUserByEmail(email: string): Promise<User> {
        if (this.USERS_TABLE.some(u => u.email === email)) {
            // This should never happen, implementation must check this before calling this method
            throw new Error("Internal: Email already exists");
        }

        const user: User = {
            userId: uuid.v4(),
            email: email
        };

        this.USERS_TABLE.push(user);

        return user;
    }

    /** Lists user data */
    public async listUsers(): Promise<User[]> {
        return Promise.resolve(this.USERS_TABLE);
    }

    public async getOpenIdUser(providerName: string, sub: string): Promise<OpenIDUser | null> {
        return this.OPENID_USERS.find(row => row.providerName === providerName && row.sub === sub) || null;
    }

    public async createOpenIdUser(openIdUser: OpenIDUser): Promise<void> {
        if (!this.USERS_TABLE.some(u => u.userId === openIdUser.userId)) {
            // This should never happen, implementation must check this before calling this method
            // This is like a FK constraint
            throw new Error("Internal: UserId not exists");
        }

        this.OPENID_USERS.push(openIdUser);

    }
}