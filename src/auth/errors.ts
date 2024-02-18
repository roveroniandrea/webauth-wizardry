import { ExtendedError } from '../types/error';

/** The user is authenticated correctly but results banned */
export class UserBannedError extends ExtendedError {
    constructor() {
        super(401, "User is banned");
    }
}


/** Generic bad request (missing or malformed data) */
export class BadRequestError extends ExtendedError {
    constructor() {
        super(400, "Bad request");
    }
}


/** Returned if signing ends with any type of error */
export class UserNotFoundError extends ExtendedError {
    constructor() {
        super(404, "User not found");
    }
}


/** Returned if the user nas no permission to access that route or resource */
export class UnauthorizedError extends ExtendedError {
    constructor() {
        super(401, "Unauthorized");
    }
}