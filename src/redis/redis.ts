import { createClient, RedisClientType } from 'redis';

let redisClient: RedisClientType | null = null;

/** Initializes Redis client */
export async function initRedisClient(): Promise<void> {
    redisClient = createClient();

    await redisClient
        // Redis will automatically try to reconnect
        .on('error', err => console.log('Redis Client Error', err))
        .on('ready', () => console.log('Redis is ready'))
        .connect();
}

/** Used internally to assert that Redis has been initialized via `initRedisClient` */
function assertClient(redisClient: RedisClientType | null): redisClient is RedisClientType {
    if (!redisClient) {
        throw new Error("Redis client not initialized");
    }

    return true;
}


/** Sets a refresh token as valid */
export async function setRefreshTokenValid(jti: string, ttlSeconds: number): Promise<void> {
    if (assertClient(redisClient)) {
        // Exact value is not really important, but is setted as the jti itself

        // Setting a key for each valid RT allows to keep stored only active RT,
        // like some minutes before they're being used to refresh an AT, or for their entire lifetime
        // Doing the opposite would result in keeping track of all the invalid RT, including those used for every AT renewal
        redisClient.setEx(`RT_JTI_${jti}`, ttlSeconds, jti);
    }
}

/** Checks if a refresh token is still considered valid */
export async function isRefreshTokenValid(jti: string): Promise<boolean> {
    if (assertClient(redisClient)) {
        // A RT is valid if its key exists
        const value = await redisClient.get(`RT_JTI_${jti}`);

        return value === jti;
    }

    return false;
}


/** Marks a refresh token as no more valid (expired) */
export async function setRefreshTokenInvalid(jti: string): Promise<void> {
    if (assertClient(redisClient)) {
        redisClient.del(`RT_JTI_${jti}`);
    }
}


/** Checks if an access token is still considered valid */
export async function isAccessTokenValid(jti: string): Promise<boolean> {
    if (assertClient(redisClient)) {
        // Opposite from RT, access tokens are valid if not present on Redis
        // This has no particular advantage over doing the opposite,
        // but since AT have a short lifetime, we just need to track invalid tokens for a small amont of time,
        // and maybe never if the user closes the page before AT expiration
        const keyCount: number = await redisClient.exists(`AT_JTI_${jti}`);

        return keyCount === 0;
    }

    return false;
}

/** Marks an access token as no more valid (expired) */
export async function setAccessTokenInvalid(jti: string, ttlSeconds: number): Promise<void> {
    if (assertClient(redisClient)) {
        redisClient.setEx(`AT_JTI_${jti}`, ttlSeconds, jti);
    }
}