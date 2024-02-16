import { RedisClientType } from 'redis';
import { clearAndInvalidateJwtTokens, setJwtTokensInCookies } from '../jwt/jwt';
import { ExpressMiddleware } from '../types/express';
import { assertAuth } from './auth';
import { ExtendedError } from '../types/error';

/** 
 * Like `setJwtTokenInCookie` but as a middleware that uses `req.user` as input
 */
export function setJwtTokensInCookieMiddleware(redisClient: RedisClientType): ExpressMiddleware {
    return async (req, res, next) => {
        if (req.user) {
            await setJwtTokensInCookies(redisClient, req.user, res);
        }

        res.status(200).send("OK");

        next();
    }
}


/**
 * Alternative to `assertAuth`, but as a middleware
 */
export function assertAuthMiddleware(): ExpressMiddleware {
    return (req, res, next) => {
        try {
            // If assert auth succeeds, proceed normally
            assertAuth(req);
            next();
        }
        catch (ex) {
            next(ex);
        }
    }
}

/**
 * Opposite of `assertAuthMiddleware`
 */
export function assertNoAuthMiddleware(): ExpressMiddleware {
    return (req, res, next) => {
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
export function clearAndInvalidateJwtTokensMiddleware(redisClient: RedisClientType): ExpressMiddleware {
    return async (req, res, next) => {
        await clearAndInvalidateJwtTokens(redisClient, req, res);

        next();
    }
}