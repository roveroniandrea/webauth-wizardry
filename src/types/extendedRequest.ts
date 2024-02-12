import { Request } from 'express';
import { User } from './user';

/** Express request extended with user data extracted from jwt token (or generated upon signin/signup) */
export type ExtendedRequest = Request & {
    user?: User;
}