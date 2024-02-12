import { User } from '../types/user';
import { v4 as uuidV4 } from 'uuid';
import { hash as bcryptHash, compare as bcryptCompare } from 'bcrypt';

const USERS_TABLE: User[] = [];

const PASSWORD_BY_USER: Map<string, string> = new Map<string, string>();


export async function createUserByEmailPassword(email: string, password: string): Promise<User> {
    if (USERS_TABLE.some(u => u.email === email)) {
        throw new Error("Email already used");
    }

    const user: User = {
        userId: uuidV4(),
        email: email
    };

    USERS_TABLE.push(user);

    const hashedPw = await bcryptHash(password, 10);
    PASSWORD_BY_USER.set(user.userId, hashedPw);

    return user;
}


export async function getUserByEmailPassword(email: string, password: string): Promise<User | null> {
    const user: User | null = USERS_TABLE.find(u => u.email === email) || null;

    if (user) {
        const hashedPw = PASSWORD_BY_USER.get(user.userId) || null;

        if (hashedPw) {
            const isPwOk = await bcryptCompare(password, hashedPw);

            if (isPwOk) {
                return user;
            }
        }
    }

    return null;
}

export async function getUserByUserId(userId: string): Promise<User> {
    const user: User | null = USERS_TABLE.find(u => u.userId === userId) || null;

    if (!user) {
        throw new Error("User not found");
    }

    return user;
}

export async function listUsers(): Promise<User[]> {
    return Promise.resolve(USERS_TABLE);
}