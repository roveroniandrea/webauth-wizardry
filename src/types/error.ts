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