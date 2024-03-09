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


/** Express response extended to always provide an object as response */
export type ExtendedResponse<T = null> = Response<{
    error: string | null;
    data: T;
}>

export type ExpressMiddleware<ResponseType = null> = (req: ExtendedRequest, res: ExtendedResponse<ResponseType>, next: NextFunction) => void | Promise<void>;