import { Request } from 'express';
import { User } from './user';

export type ExtendedRequest = Request & {
    user?: User;
}