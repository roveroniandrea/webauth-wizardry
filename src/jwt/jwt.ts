import { Response } from 'express';
import { Jwt, JwtPayload, SignCallback, VerifyErrors, sign, verify } from 'jsonwebtoken';
import * as uuid from 'uuid';
import { setRefreshTokenValid } from '../redis/redis';
import { ExtendedError } from '../types/error';
import { DecodedJwt, EncodedJwt } from '../types/jwt';
import { User } from '../types/user';

/** Name of the cookie where to store the jwt payload */
export const AT_COOKIE_NAME: string = 'token';

export const RT_COOKIE_NAME: string = 'rt-token';

/** Access token and jwt payload validity expressed in seconds */
const AT_EXPIRES_IN_SECONDS: number = 60 * 10; // 10 minutes

/** Refresh token validity in seconds */
const RT_EXPIRES_IN_SECONDS: number = 3600 * 24 * 7; // 1 week



/** 
 * Generates both access and refresh tokens.
 * Access token can hold some data, while refresh token has no data and is used for just the subject
 */
async function generateTokens<Data extends { userId: string }>(data: Data, expiresInSeconds: number): Promise<{
    accessToken: EncodedJwt;
    refreshToken: EncodedJwt;
}> {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
        throw new ExtendedError(500, "Missing configuration"), null;
    }

    const signCallback = (res: Function, rej: Function, jti: string) => {
        return ((err: Error | null, encoded: string | undefined) => {
            // Throw an error if token if something goes wrong
            if (err || !encoded) {
                rej(err || new ExtendedError(500));
            }
            else {
                res({
                    jti: jti,
                    encoded: encoded
                });
            }
        }) as SignCallback;
    }

    const [encodedAT, encodedRT]: [EncodedJwt, EncodedJwt] = await Promise.all([
        // Access token holds data
        new Promise<EncodedJwt>((res, rej) => {
            const atJti: string = uuid.v4();
            // Date is put into a nested `jwtPayload.data` property,
            // because the token contains some more top-level properties that do not need to be passed elsewhere
            sign({ data: data }, jwtSecret, {
                expiresIn: expiresInSeconds,
                subject: data.userId,
                jwtid: atJti
            }, signCallback(res, rej, atJti));
        }),
        // Refresh token does not need to store data, the subject is sufficient
        new Promise<EncodedJwt>((res, rej) => {
            const rtJti: string = uuid.v4();
            sign({}, jwtSecret, {
                expiresIn: expiresInSeconds,
                subject: data.userId,
                jwtid: rtJti
            }, signCallback(res, rej, rtJti));
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
export async function decodeAccessToken(encoded: string): Promise<DecodedJwt<User> | null> {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
        throw new ExtendedError(500, "Missing configuration"), null;
    }

    const verified = await new Promise<DecodedJwt<User> | null>((res, _) => {
        verify(encoded, jwtSecret, {
            complete: true
        }, (err: VerifyErrors | null, decoded?: Jwt) => {
            // Token verification might go wrong (for example if the token is expired)
            if (err || !decoded) {
                res(null);
                return;
            }

            // Payload might not exist (malformed token)
            res(decoded?.payload ? {
                jti: (decoded.payload as JwtPayload).jti || '',
                sub: (decoded.payload as JwtPayload).sub || '',
                data: (decoded.payload as JwtPayload).data
            } : null);
        });
    });

    return verified;
}


/** 
 * Decodes a refresh token, returning the userId (subject) it's assigned to
 */
export async function decodeRefreshToken(encoded: string): Promise<DecodedJwt | null> {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
        throw new ExtendedError(500, "Missing configuration"), null;
    }

    const verified = await new Promise<DecodedJwt | null>((res, _) => {
        verify(encoded, jwtSecret, {
            complete: true
        }, (err: VerifyErrors | null, decoded?: Jwt) => {
            // Token verification might go wrong (for example if the token is expired)
            if (err || !decoded) {
                res(null);
                return;
            }

            res({
                jti: (decoded.payload as JwtPayload).jti || '',
                sub: (decoded.payload as JwtPayload).sub || '',
                data: {}
            });
        });
    });

    return verified;
}


/**
 * Generates both access and refresh tokens and sets them as cookies
 */
export async function setJwtTokenInCookie(user: User, res: Response): Promise<void> {
    const { accessToken, refreshToken } = await generateTokens(user, AT_EXPIRES_IN_SECONDS);

    // Setting refresh token as valid
    // Note: AT are considered valid by default
    await setRefreshTokenValid(refreshToken.jti, RT_EXPIRES_IN_SECONDS);

    res.cookie(AT_COOKIE_NAME, accessToken.encoded, {
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

    res.cookie(RT_COOKIE_NAME, refreshToken.encoded, {
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
