/** Defines an encoded JWT with the corresponding jti (token identifier) */
export type EncodedJwt = {
    /** Unique token identifier */
    jti: string;
    encoded: string;
}

/** Defines a decoded jwt, with it jwt (identified), sub (referred userId) and data */
export type DecodedJwt<Data = Record<never, never>> = {
    /** Unique token identifier */
    jti: string;
    /** Referred userId */
    sub: string;
    data: Data;
}