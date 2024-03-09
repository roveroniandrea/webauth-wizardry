import CookieStrategy from 'passport-cookie';
import { Strategy, AuthenticateCallback } from 'passport';
import { clearAndInvalidateJwtTokens, decodeAccessToken, decodeRefreshToken, setJwtTokensInCookies } from '../jwt/jwt';
import { isAccessTokenValid, isRefreshTokenValid, setRefreshTokenInvalid } from '../redis/redis';
import { ExtendedError, ExtendedNextFunction } from '../types/error';
import { User } from '../types/user';
import { WebauthWizardryConfig } from '../types/webauth-wizardry';
import { BadRequestError, UserBannedError } from './errors';
import { ExtendedRequest, ExtendedResponse } from '../types/express';


export function cookieStrategy(config: WebauthWizardryConfig): Strategy {
    return new CookieStrategy({
        cookieName: config.cookieConfig.ATCookieName,
        signed: true,
        passReqToCallback: true
    }, async (req: Request, token: string, done: (err: ExtendedError | null, user: User | null) => void) => {
        // If there's a token, decode and extract it
        // This will never throw an error, just null in case the user cannot be extracted for any reason
        const decodedAccessToken = await decodeAccessToken(token, config.SECRETS.JWT_SECRET);

        // Also, check access token validity
        const accessTokenValid: boolean = decodedAccessToken ? await isAccessTokenValid(config.redisClient, decodedAccessToken.jti) : false;

        // TODO: Optionally, here it can be verified if user is not banned, in order to block every request even before AT expires
        // However this would increase the number of requests to Redis and introduce some delay on every request
        const isUserBanned: boolean = (decodedAccessToken?.data?.userId) ? false : false;

        if (isUserBanned) {
            done(new UserBannedError(), null);
        }
        else {
            // If access token is present and valid, return the user. Otherwise, access token will be cleared later
            done(null, (decodedAccessToken?.data && accessTokenValid) ? decodedAccessToken.data : null);
        }

    })
}


export function cookieAuthenticateCallback(config: WebauthWizardryConfig, req: ExtendedRequest, res: ExtendedResponse, next: ExtendedNextFunction): AuthenticateCallback {
    return async (err: any, user?: User | false | null, info?: any, status?: any) => {
        // A custom error can be passed by `done` callback on passport.authenticate
        // If there's an error, throw it
        if (err) {
            next(err);
            return;
        }

        // For unauthenticated requests (meaning the user cannot be recovered from access token) `user` will be at `false`
        // TODO: This might be converted into a custom strategy or middleware?
        if (!user) {
            // If for any reason the user cannot be extracted from access token (missing cookie, jwt invalid), try refreshing the session
            const oldRefreshToken: string = req.signedCookies[config.cookieConfig.RTCookieName];

            // Decode the extracted refresh token and check its validity
            const decodedOldRefreshToken = oldRefreshToken ? await decodeRefreshToken(oldRefreshToken, config.SECRETS.JWT_SECRET) : null;
            const refreshTokenValid: boolean = decodedOldRefreshToken ? await isRefreshTokenValid(config.redisClient, decodedOldRefreshToken.jti) : false;

            if (decodedOldRefreshToken && refreshTokenValid) {
                // If refresh token is valid and thus a userId can be extracted, regenerate both

                // First, invalidate the current refresh token (AT is already invalid) TODO: Maybe get and delete immedately using redis.getdel()
                await setRefreshTokenInvalid(config.redisClient, decodedOldRefreshToken.jti)

                // Then try to reauthenticate
                user = await config.dbClient.getUserByUserId(decodedOldRefreshToken.sub);

                // TODO: Check if user is not banned or something else, and throw an error in this case
                const isUserBanned: boolean = user ? false : false;

                if (!user || isUserBanned) {
                    // If user does not exist or has been banned,
                    // clear both cookies (refresh token cookie surely exists)
                    await clearAndInvalidateJwtTokens(config.redisClient, req, res, {
                        jwtSecret: config.SECRETS.JWT_SECRET,
                        ATCookieName: config.cookieConfig.ATCookieName,
                        ATExpiresInSeconds: config.cookieConfig.ATExpiresInSeconds,
                        RTCookieName: config.cookieConfig.RTCookieName
                    });

                    if (isUserBanned) {
                        // Special error if user is banned
                        next(new UserBannedError());
                        return;
                    }

                    // Otherwise, RT was pointing to an inexistent user for some reason
                    // Return a generic error
                    next(new BadRequestError());
                    return;
                }
            }

            // Here, the user might have been reauthenticated via refresh token or might be totally unauthenticated because of no refresh token
            if (user) {
                // If authenticated, set new tokens in cookies
                await setJwtTokensInCookies(config.redisClient, user, res, {
                    jwtSecret: config.SECRETS.JWT_SECRET,
                    ATCookieName: config.cookieConfig.ATCookieName,
                    RTCookieName: config.cookieConfig.RTCookieName,
                    ATExpiresInSeconds: config.cookieConfig.ATExpiresInSeconds,
                    RTExpiresInSeconds: config.cookieConfig.RTExpiresInSeconds
                });
            }
        }

        // At this point, if AT was valid, request is authenticated
        // Otherwise, depends on RT:
        //      If RT was valid, both tokens have been regenerated and set as cookies, and previous RT was set as invalid
        //      If RT was not valid or user was banned, both tokens need to be cleared and set as invalid (see below)

        // Proceed with or without the user
        req.user = user || undefined;

        if (!req.user) {
            // If request is not authenticated (for any reason or for any missing/invalid token)
            // Proceed to invalidate everything (AT or RT) present in the request
            await clearAndInvalidateJwtTokens(config.redisClient, req, res, {
                jwtSecret: config.SECRETS.JWT_SECRET,
                ATCookieName: config.cookieConfig.ATCookieName,
                RTCookieName: config.cookieConfig.RTCookieName,
                ATExpiresInSeconds: config.cookieConfig.ATExpiresInSeconds
            });
        }

        next();
    };
}