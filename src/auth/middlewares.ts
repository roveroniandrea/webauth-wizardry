import { NextFunction, Response } from 'express';
import { setJwtTokensInCookies } from '../jwt/jwt';
import { ExtendedNextFunction } from '../types/error';
import { ExtendedRequest } from '../types/extendedRequest';
import { assertAuth } from './auth';

/** 
 * Like `setJwtTokenInCookie` but as a middleware that uses `req.user` as input
 */
export async function setJwtTokensInCookieMiddleware(req: ExtendedRequest, res: Response, next: ExtendedNextFunction): Promise<void> {
    if (req.user) {
        await setJwtTokensInCookies(req.user, res);
    }

    res.status(200).send("OK");

    next();
}


/**
 * Alternative to `assertAuth`, but as a middleware
 */
export function assertAuthMiddleware() {
    return (req: ExtendedRequest, res: Response, next: NextFunction) => {
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
 * Like `clearAndInvalidateJwtTokens` but as a middleware
*/
export async function clearAndInvalidateJwtTokensMiddleware(req: ExtendedRequest, res: Response, next: ExtendedNextFunction) {
    await clearAndInvalidateJwtTokensMiddleware(req, res, next);

    next();
}