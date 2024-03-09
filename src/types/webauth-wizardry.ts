import { RedisClientType } from 'redis';
import { DatabaseInterface } from '../db/databaseInterface';
import { Router } from 'express';

/** Config related to server */
type ServerConfig = {
    serverBaseUrl: string;
}

type CookieConfig = {
    ATCookieName: string;
    RTCookieName: string;
    ATExpiresInSeconds: number;
    RTExpiresInSeconds: number;
}

export type WebauthWizardryConfig = {
    /** Express router */
    router: Router;

    /** Configuration related to the server */
    serverConfig: ServerConfig;

    /** Secrets for cookie and jwt management */
    SECRETS: {
        COOKIE_PARSER_SECRET: string;
        JWT_SECRET: string;
    };
    /** Config for cookies and jwt */
    cookieConfig: CookieConfig;
    /** Redis client */
    redisClient: RedisClientType;
    /** Database client */
    dbClient: DatabaseInterface;
}

export type OpenIDProvidersConfig = {
    stateCookieName: string;
    nonceCookieName: string;
    maxAgeTimeoutInSeconds: number;
}