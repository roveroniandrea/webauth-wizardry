import { ExtendedError } from '../types/error';
import { ExtendedRequest } from '../types/express';
import { User } from '../types/user';
import { UnauthorizedError } from './errors';

/** Asserts that the user has been correctly retrieved from the request.
 * Throws a 401 error if not.
 * TODO: Add support for specific authorizations
 */
export function assertAuth(req: ExtendedRequest): User {
    if (!req.user) {
        throw new UnauthorizedError();
    }

    return req.user;
}