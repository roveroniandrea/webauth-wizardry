import { Response } from 'express';
import { Jwt, JwtPayload, SignCallback, VerifyErrors, sign, verify } from 'jsonwebtoken';
import * as uuid from 'uuid';
import { ExtendedError, ExtendedNextFunction } from '../types/error';
import { ExtendedRequest } from '../types/extendedRequest';
import { User } from '../types/user';

/** Name of the cookie where to store the jwt payload */
export const AT_COOKIE_NAME: string = 'token';

export const RT_COOKIE_NAME: string = 'rt-token';

/** Access token and jwt payload validity expressed in seconds */
const AT_EXPIRES_IN_SECONDS: number = 3600;

/** Refresh token validity in seconds */
const RT_EXPIRES_IN_SECONDS: number = 3600 * 24 * 7;


/** Generates both access and refresh tokens.
 * Access token can hold some data, while refresh token has no data and is used for just the subject
 */
async function generateTokens<Data extends { userId: string }>(data: Data, expiresInSeconds: number): Promise<{
    accessToken: string;
    refreshToken: string;
}> {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
        throw new ExtendedError(500, "Missing configuration"), null;
    }

    const signCallback = (res: (value: string | PromiseLike<string>) => void, rej: (reason?: any) => void) => {
        return ((err: Error | null, encoded: string | undefined) => {
            // Throw an error if token if something goes wrong
            if (err || !encoded) {
                rej(err || new ExtendedError(500));
            }
            else {
                res(encoded);
            }
        }) as SignCallback;
    }

    const [encodedAT, encodedRT]: [string, string] = await Promise.all([
        // Access token holds data
        new Promise<string>((res, rej) => {
            // Date is put into a nested `jwtPayload.data` property,
            // because the token contains some more top-level properties that do not need to be passed elsewhere
            sign({ data: data }, jwtSecret, {
                expiresIn: expiresInSeconds,
                subject: data.userId,
                jwtid: uuid.v4()
            }, signCallback(res, rej));
        }),
        // Refresh token does not need to store data, the subject is sufficient
        new Promise<string>((res, rej) => {
            sign({}, jwtSecret, {
                expiresIn: expiresInSeconds,
                subject: data.userId,
                jwtid: uuid.v4()
            }, signCallback(res, rej));
        })
    ]);

    return {
        accessToken: encodedAT,
        refreshToken: encodedRT
    };
}

/** 
 * Decodes an encoded access token, checking its validity and the presence of a User in its data.
 * Returns null if a user cannot be extracted from the token
 */
export async function decodeAccessToken(encoded: string): Promise<User | null> {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
        throw new ExtendedError(500, "Missing configuration"), null;
    }

    const verified = await new Promise<User | null>((res, _) => {
        verify(encoded, jwtSecret, {
            complete: true
        }, (err: VerifyErrors | null, decoded?: Jwt) => {
            // Token verification might go wrong (for example if the token is expired)
            if (err || !decoded) {
                res(null);
                return;
            }

            // Payload might not exist (malformed token)
            const payloadData: User = (decoded.payload as JwtPayload)["data"];
            res(payloadData || null);
        });
    });

    return verified;
}

/** Decodes a refresh token, returning the userId (subject) it's assigned to */
export async function decodeRefreshToken(encoded: string): Promise<string | null> {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
        throw new ExtendedError(500, "Missing configuration"), null;
    }

    const verified = await new Promise<string | null>((res, _) => {
        verify(encoded, jwtSecret, {
            complete: true
        }, (err: VerifyErrors | null, decoded?: Jwt) => {
            // Token verification might go wrong (for example if the token is expired)
            if (err || !decoded) {
                res(null);
                return;
            }

            res((decoded.payload as JwtPayload)?.["sub"] || null);
        });
    });

    return verified;
}


export async function setJwtTokenInCookie(user: User, res: Response): Promise<void> {
    const { accessToken, refreshToken } = await generateTokens(user, AT_EXPIRES_IN_SECONDS);

    res.cookie(AT_COOKIE_NAME, accessToken, {
        // Setting expiration in milliseconds
        expires: undefined,
        maxAge: AT_EXPIRES_IN_SECONDS * 1000,
        // Not available to JS
        httpOnly: true,
        // Sent only to this domain
        sameSite: "strict",
        // Available only in https
        secure: true,
        // Cookie is signed to ensure client does not modify it
        signed: true
    });

    res.cookie(RT_COOKIE_NAME, refreshToken, {
        // Setting expiration in milliseconds
        expires: undefined,
        maxAge: RT_EXPIRES_IN_SECONDS * 1000,
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

/** Middleware that puts the `req.user` data into a jwt payload and sets it into a cookie */
export async function setJwtTokenInCookieMiddleware(req: ExtendedRequest, res: Response, next: ExtendedNextFunction): Promise<void> {
    if (req.user) {
        await setJwtTokenInCookie(req.user, res);
    }

    res.status(200).send("OK");

    next();
}