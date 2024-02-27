import { NextFunction, Request, Response } from 'express';
import { User as ExtendedUser } from './user';

// I must override Express `req.user` property, otherwise TS gets antry when using `ExtendedRequest`
declare global {
    namespace Express {
        interface User extends ExtendedUser { }
    }
}

/** Express request extended with user data extracted from jwt token (or generated upon signin/signup) */
export type ExtendedRequest = Request & {
    user?: ExtendedUser;
}


export type ExpressMiddleware = (req: ExtendedRequest, res: ExtendedResponse, next: NextFunction) => void | Promise<void>;

/** Express response extended to always provide an object as response */
export type ExtendedResponse<T = null> = Response<{
    error: string | null;
    data: T;
}>