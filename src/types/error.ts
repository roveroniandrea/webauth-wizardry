/** Custom error passed into `next` Express function.
 * Allows to specify a status code and an optional message to send
 */
export class ExtendedError extends Error {
    constructor(public readonly statusCode: number, responseMessage?: string) {
        super(responseMessage || "Unexpected error");
    }
}

/** `next` express function that accepts a `ExtendedError` */
export type ExtendedNextFunction = {
    (err?: ExtendedError): void;
}



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