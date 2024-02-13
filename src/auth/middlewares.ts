import { NextFunction, Response } from 'express';
import { setJwtTokenInCookie } from '../jwt/jwt';
import { ExtendedNextFunction } from '../types/error';
import { ExtendedRequest } from '../types/extendedRequest';
import { assertAuth } from './auth';

/** 
 * Like `setJwtTokenInCookie` but as a middleware that uses `req.user` as input
 */
export async function setJwtTokenInCookieMiddleware(req: ExtendedRequest, res: Response, next: ExtendedNextFunction): Promise<void> {
    if (req.user) {
        await setJwtTokenInCookie(req.user, res);
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