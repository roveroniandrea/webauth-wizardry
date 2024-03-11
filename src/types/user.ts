
/** Basic user data. This data will be available in jwt payload */
export type User = {
    userId: string;
    email: string;
}

/** Represents the basic data that refers to a user authenticated via openID.
 * This identifies a user for a specific provider, but user data needs to be retrieved in a separate way
 */
export type OpenIDUser = {
    providerName: string;
    sub: string;
    userId: string;
}
