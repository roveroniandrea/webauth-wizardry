import { Response } from 'express';
import { Jwt, JwtPayload, VerifyErrors, sign, verify } from 'jsonwebtoken';
import * as uuid from 'uuid';
import { ExtendedError, ExtendedNextFunction } from '../types/error';
import { ExtendedRequest } from '../types/extendedRequest';
import { User } from '../types/user';

/** Name of the cookie where to store the jwt payload */
export const JWT_COOKIE_NAME: string = 'token';

/** Jwt payload validity expressed in seconds */
export const JWT_EXPIRES_IN_SECONDS: number = 3600;


/** Generates a jwt token with custom data */
async function generateToken(data: User, expiresInSeconds: number): Promise<string> {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
        throw new ExtendedError(500, "Missing configuration"), null;
    }

    const encoded: string = await new Promise<string>((res, rej) => {
        // Date is put into a nested `jwtPayload.data` property,
        // because the token contains some more top-level properties that do not need to be passed elsewhere
        sign({ data: data }, jwtSecret, {
            expiresIn: expiresInSeconds,
            subject: data.userId,
            jwtid: uuid.v4()
        }, (err: Error | null, encoded: string | undefined) => {
            // Throw an error if token if something goes wrong
            if (err || !encoded) {
                rej(err || new ExtendedError(500));
            }
            else {
                res(encoded);
            }
        });
    });

    return encoded;
}

/** Decodes an encoded token, asserting its validity and the presence of a User in its data.
 * Throws an error if decode goes wrong for any reason, like token expired or no User data
 */
export async function assertDecodeToken(encoded: string): Promise<User> {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
        throw new ExtendedError(500, "Missing configuration"), null;
    }

    const verified = await new Promise<User>((res, rej) => {
        verify(encoded, jwtSecret, {
            complete: true
        }, (err: VerifyErrors | null, decoded?: Jwt) => {
            // Token verification might go wrong (for example if the token is expired)
            if (err || !decoded) {
                rej(err || new ExtendedError(400, "Not authenticated"));
            }
            else {
                const payloadData: User = (decoded.payload as JwtPayload)["data"];

                // Payload might not exist (malformed token)
                if (!payloadData) {
                    rej(new ExtendedError(400, "Not authenticated"));
                }
                else {
                    res(payloadData);
                }
            }
        });
    });

    return verified;
}

/** Middleware that puts the `req.user` data into a jwt payload and sets it into a cookie */
export async function setJwtTokenInCookieMiddleware(req: ExtendedRequest, res: Response, next: ExtendedNextFunction): Promise<void> {
    if (req.user) {
        const token: string = await generateToken(req.user, JWT_EXPIRES_IN_SECONDS);

        res.cookie(JWT_COOKIE_NAME, token, {
            // Setting expiration in milliseconds
            expires: undefined,
            maxAge: JWT_EXPIRES_IN_SECONDS * 1000,
            // Not available to JS
            httpOnly: true,
            // Sent only to this domain
            sameSite: "strict",
            // Available only in https
            secure: true,
            // Cookie is signed to ensure client does not modify it
            signed: true
        });
    }

    res.status(200).send("OK");

    next();
}