import { Response } from 'express';
import { Jwt, JwtPayload, SignCallback, VerifyErrors, sign, verify } from 'jsonwebtoken';
import { RedisClientType } from 'redis';
import * as uuid from 'uuid';
import { setAccessTokenInvalid, setRefreshTokenInvalid, setRefreshTokenValid } from '../redis/redis';
import { ExtendedError } from '../types/error';
import { ExtendedRequest, ExtendedResponse } from '../types/express';
import { DecodedJwt, EncodedJwt } from '../types/jwt';
import { User } from '../types/user';

/** 
 * Generates both access and refresh tokens.
 * Access token can hold some data, while refresh token has no data and is used for just the subject
 */
async function generateTokens<Data extends { userId: string }>(data: Data, config: {
    ATExpiresInSeconds: number;
    RTExpiresInSeconds: number;
    jwtSecret: string;
}): Promise<{
    accessToken: EncodedJwt;
    refreshToken: EncodedJwt;
}> {

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
            sign({ data: data }, config.jwtSecret, {
                expiresIn: config.ATExpiresInSeconds,
                subject: data.userId,
                jwtid: atJti
            }, signCallback(res, rej, atJti));
        }),
        // Refresh token does not need to store data, the subject is sufficient
        new Promise<EncodedJwt>((res, rej) => {
            const rtJti: string = uuid.v4();
            sign({}, config.jwtSecret, {
                expiresIn: config.RTExpiresInSeconds,
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
export async function decodeAccessToken(encoded: string, jwtSecret: string): Promise<DecodedJwt<User> | null> {

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
export async function decodeRefreshToken(encoded: string, jwtSecret: string): Promise<DecodedJwt | null> {

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
export async function setJwtTokensInCookies(redisClient: RedisClientType, user: User, res: ExtendedResponse, config: {
    jwtSecret: string;
    ATCookieName: string;
    RTCookieName: string;
    ATExpiresInSeconds: number;
    RTExpiresInSeconds: number;
}): Promise<void> {
    const { accessToken, refreshToken } = await generateTokens(user, {
        ATExpiresInSeconds: config.ATExpiresInSeconds,
        RTExpiresInSeconds: config.RTExpiresInSeconds,
        jwtSecret: config.jwtSecret
    });

    // Setting refresh token as valid
    // Note: AT are considered valid by default
    await setRefreshTokenValid(redisClient, refreshToken.jti, config.RTExpiresInSeconds);

    res.cookie(config.ATCookieName, accessToken.encoded, {
        // Setting expiration in milliseconds
        expires: undefined,
        maxAge: config.ATExpiresInSeconds * 1000,
        // Not available to JS
        httpOnly: true,
        // Sent only from same domain requests
        sameSite: "strict",
        // Available only in https
        secure: true,
        // Cookie is signed to ensure client does not modify it
        signed: true
    });

    res.cookie(config.RTCookieName, refreshToken.encoded, {
        // Setting expiration in milliseconds
        expires: undefined,
        maxAge: config.RTExpiresInSeconds * 1000,
        // Not available to JS
        httpOnly: true,
        // Sent only from same domain requests
        sameSite: "strict",
        // Available only in https
        secure: true,
        // Cookie is signed to ensure client does not modify it
        signed: true
    });
}


/** 
 * Checks for both AT and RT in cookies and, if present, both invalidates them and removes them from cookies.
 * This is useful for competely logout a user
*/
export async function clearAndInvalidateJwtTokens(redisClient: RedisClientType, req: ExtendedRequest, res: ExtendedResponse, config: {
    jwtSecret: string;
    ATCookieName: string;
    RTCookieName: string;
    ATExpiresInSeconds: number;
}) {
    const accessToken: string | undefined = req.signedCookies[config.ATCookieName];
    const refreshToken: string | undefined = req.signedCookies[config.RTCookieName];

    const decodedAccessToken = accessToken ? await decodeAccessToken(accessToken, config.jwtSecret) : null;
    const decodedRefreshToken = refreshToken ? await decodeRefreshToken(refreshToken, config.jwtSecret) : null;

    await Promise.all([
        decodedAccessToken ? setAccessTokenInvalid(redisClient, decodedAccessToken.jti, config.ATExpiresInSeconds) : null,
        decodedRefreshToken ? setRefreshTokenInvalid(redisClient, decodedRefreshToken.jti) : null
    ]);


    if (accessToken) {
        res.clearCookie(config.ATCookieName);
    }

    if (refreshToken) {
        res.clearCookie(config.RTCookieName);
    }

}