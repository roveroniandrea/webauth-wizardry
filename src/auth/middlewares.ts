import { RedisClientType } from 'redis';
import { clearAndInvalidateJwtTokens, setJwtTokensInCookies } from '../jwt/jwt';
import { ExtendedError, ExtendedNextFunction } from '../types/error';
import { ExpressMiddleware, ExtendedRequest, ExtendedResponse } from '../types/express';
import { assertAuth } from './auth';
import { UnauthorizedError } from './errors';

/** 
 * Like `setJwtTokenInCookie` but as a middleware that uses `req.user` as input.
 * 
 */
export function setJwtTokensInCookieMiddleware(redisClient: RedisClientType, config: {
    jwtSecret: string;
    ATCookieName: string;
    RTCookieName: string;
    ATExpiresInSeconds: number;
    RTExpiresInSeconds: number;
}): ExpressMiddleware {
    return async (req: ExtendedRequest, res: ExtendedResponse, next: ExtendedNextFunction) => {
        if (req.user) {
            await setJwtTokensInCookies(redisClient, req.user, res, config);
        }

        next();
    }
}


/**
 * Alternative to `assertAuth`, but as a middleware
 * TODO: Add support for specific authorizations
 */
export function assertAuthMiddleware(): ExpressMiddleware {
    return (req: ExtendedRequest, res: ExtendedResponse, next: ExtendedNextFunction) => {
        try {
            // If assert auth succeeds, proceed normally
            assertAuth(req);
            next();
        }
        catch (ex) {
            next(ex as UnauthorizedError);
        }
    }
}

/**
 * Opposite of `assertAuthMiddleware`
 */
export function assertNoAuthMiddleware(): ExpressMiddleware {
    return (req: ExtendedRequest, res: ExtendedResponse, next: ExtendedNextFunction) => {
        try {
            // If assert auth succeeds, throw an error
            assertAuth(req);
            next(new ExtendedError(400, "Already authenticated"));
        }
        catch (ex) {
            // Vice versa, proceed
            next();
        }
    }
}


/** 
 * Like `clearAndInvalidateJwtTokens` but as a middleware
*/
export function clearAndInvalidateJwtTokensMiddleware(redisClient: RedisClientType, config: {
    jwtSecret: string;
    ATCookieName: string;
    RTCookieName: string;
    ATExpiresInSeconds: number;
}): ExpressMiddleware {
    return async (req: ExtendedRequest, res: ExtendedResponse, next: ExtendedNextFunction) => {
        await clearAndInvalidateJwtTokens(redisClient, req, res, config);

        next();
    }
}