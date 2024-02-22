import bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';

/**
 * Generates a cryptographically secure string,
 * which is also url safe, meaning it can be passed in browser url without the need to encode/decode it
 */
export async function randomUrlSafeString(length: number): Promise<string> {
    const str = new Promise<string>((res, rej) => {
        randomBytes(length, function (err, buffer) {
            if (err) {
                rej(err);
                return;
            }

            const encoded = buffer.toString('hex');

            res(encoded);
        });
    })

    return str;
}


/**
 * Hashes a password (one way operation)
 */
export async function hashPassword(password: string): Promise<string> {
    const hashedPw: string = await bcrypt.hash(password, 10);

    return hashedPw;
}