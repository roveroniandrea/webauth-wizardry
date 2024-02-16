import { RedisClientType } from 'redis';

/** Sets a refresh token as valid */
export async function setRefreshTokenValid(redisClient: RedisClientType, jti: string, ttlSeconds: number): Promise<void> {
    // Exact value is not really important, but is setted as the jti itself

    // Setting a key for each valid RT allows to keep stored only active RT,
    // like some minutes before they're being used to refresh an AT, or for their entire lifetime
    // Doing the opposite would result in keeping track of all the invalid RT, including those used for every AT renewal
    redisClient.setEx(`RT_VALID_JTI_${jti}`, ttlSeconds, jti);
}

/** Checks if a refresh token is still considered valid */
export async function isRefreshTokenValid(redisClient: RedisClientType, jti: string): Promise<boolean> {
    // A RT is valid if its key exists
    const value = await redisClient.get(`RT_VALID_JTI_${jti}`);

    return value === jti;

    return false;
}


/** Marks a refresh token as no more valid (expired) */
export async function setRefreshTokenInvalid(redisClient: RedisClientType, jti: string): Promise<void> {
    redisClient.del(`RT_VALID_JTI_${jti}`);
}


/** Checks if an access token is still considered valid */
export async function isAccessTokenValid(redisClient: RedisClientType, jti: string): Promise<boolean> {
    // Opposite from RT, access tokens are valid if not present on Redis
    // This has no particular advantage over doing the opposite,
    // but since AT have a short lifetime, we just need to track invalid tokens for a small amont of time,
    // and maybe never if the user closes the page before AT expiration
    const keyCount: number = await redisClient.exists(`AT_INVALID_JTI_${jti}`);

    return keyCount === 0;

    return false;
}

/** Marks an access token as no more valid (expired) */
export async function setAccessTokenInvalid(redisClient: RedisClientType, jti: string, ttlSeconds: number): Promise<void> {
    redisClient.setEx(`AT_INVALID_JTI_${jti}`, ttlSeconds, jti);
}