import bcrypt from 'bcrypt';
import * as uuid from 'uuid';
import { User } from '../types/user';
import { DatabaseInterface } from './databaseInterface';


/**
 * THIS IS A DUMMY REPRESENTATION OF A CUSTOM DB
 * 
 * Feel free to use in production if you hate yourself
 */
export class DummyDB implements DatabaseInterface {

    /** Table used to store user data */
    private readonly USERS_TABLE: User[] = [];

    /** Stores hashed password for each user */
    private readonly PASSWORD_BY_USER: Map<string, string> = new Map<string, string>();

    /** Creates a user given email and password.
     * Password is hashed
     */
    public async createUserByEmailPassword(email: string, password: string): Promise<User> {
        if (this.USERS_TABLE.some(u => u.email === email)) {
            throw new Error("Email already used");
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

    /** Retrieves user data by its id */
    public async getUserByUserId(userId: string): Promise<User> {
        const user: User | null = this.USERS_TABLE.find(u => u.userId === userId) || null;

        if (!user) {
            throw new Error("User not found");
        }

        return user;
    }

    /** Lists user data */
    public async listUsers(): Promise<User[]> {
        return Promise.resolve(this.USERS_TABLE);
    }
}