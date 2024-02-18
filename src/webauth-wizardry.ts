import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import { Response, Router } from 'express';
import passport from 'passport';
import CookieStrategy from 'passport-cookie';
import { RedisClientType } from 'redis';
import { assertAuthMiddleware, assertNoAuthMiddleware, clearAndInvalidateJwtTokensMiddleware, setJwtTokensInCookieMiddleware } from './auth/middlewares';
import { DatabaseInterface } from './db/databaseInterface';
import { clearAndInvalidateJwtTokens, decodeAccessToken, decodeRefreshToken, setJwtTokensInCookies } from './jwt/jwt';
import { isAccessTokenValid, isRefreshTokenValid, setRefreshTokenInvalid } from './redis/redis';
import { ExtendedError, ExtendedNextFunction } from './types/error';
import { ExtendedRequest } from './types/express';
import { User } from './types/user';
import { BadRequestError, UserBannedError, UserNotFoundError } from './auth/errors';


const DEFAULT_COOKIE_CONFIG = {
    /** Name of the cookie where to store the jwt payload */
    ATCookieName: 'token',
    RTCookieName: 'rt-token',

    /** Access token and jwt payload validity expressed in seconds */
    ATExpiresInSeconds: 60 * 10, // 10 minutes
    /** Refresh token validity in seconds */
    RTExpiresInSeconds: 3600 * 24 * 7 // 1 week
}

type WebauthWizardryConfig = {
    /** Express router */
    router: Router;
    /** Secrets for cookie and jwt management */
    SECRETS: {
        COOKIE_PARSER_SECRET: string;
        JWT_SECRET: string;
    };
    /** Override default config for cookies and jwt */
    cookieConfig?: Partial<typeof DEFAULT_COOKIE_CONFIG>;
    /** Redis client */
    redisClient: RedisClientType;
    /** Database client */
    dbClient: DatabaseInterface;
}

export class WebauthWizardryForExpress {

    private readonly config: Omit<WebauthWizardryConfig, "cookieConfig"> & {
        cookieConfig: typeof DEFAULT_COOKIE_CONFIG;
    };

    constructor(customConfig: WebauthWizardryConfig) {
        this.config = {
            ...customConfig,
            // Start with default config for cookies, but override if specified from input
            cookieConfig: {
                ...DEFAULT_COOKIE_CONFIG,
                ...(customConfig.cookieConfig || {})
            }
        }

        // Body parser allows to populate `req.body`
        this.config.router.use(bodyParser.json());

        // Check for secrets
        if (!this.config.SECRETS.COOKIE_PARSER_SECRET || !this.config.SECRETS.JWT_SECRET) {
            throw new Error("Missing configuration");
        }
        // CookieParser sets `req.cookies` and `req.signedCookies`
        this.config.router.use(cookieParser(this.config.SECRETS.COOKIE_PARSER_SECRET));

        // Passport strategies
        this.setupCookieStrategy();

        // Always setup logout route
        this.setupLogout();
    }

    private setupCookieStrategy() {
        // Cookie strategy allows to extract token from cookies
        passport.use(new CookieStrategy({
            cookieName: this.config.cookieConfig.ATCookieName,
            signed: true,
            passReqToCallback: true
        }, async (req: Request, token: string, done: (err: ExtendedError | null, user: User | null) => void) => {
            // If there's a token, decode and extract it
            // This will never throw an error, just null in case the user cannot be extracted for any reason
            const decodedAccessToken = await decodeAccessToken(token, this.config.SECRETS.JWT_SECRET);

            // Also, check access token validity
            const accessTokenValid: boolean = decodedAccessToken ? await isAccessTokenValid(this.config.redisClient, decodedAccessToken.jti) : false;

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

        }));


        // For every request, extract the jwt payload from the cookies and verify it
        this.config.router.use((req: ExtendedRequest, res: Response, next: ExtendedNextFunction) => {

            /*
        
                A custom callback is passed in order to allow two things:
                1 - For an unauthenticated request, check if user can be refreshed via refresh token (checking user validity to be reauthenticated, like for example user not banned)
                2 - Unauthenticated requests can proceed (except for refresh token banned)
        
                This is because some endpoints might not require authentication
        
            */
            passport.authenticate("cookie", { session: false }, async (err: any, user: User | false | null, info: any, status: any) => {
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
                    const oldRefreshToken: string = req.signedCookies[this.config.cookieConfig.RTCookieName];

                    // Decode the extracted refresh token and check its validity
                    const decodedOldRefreshToken = oldRefreshToken ? await decodeRefreshToken(oldRefreshToken, this.config.SECRETS.JWT_SECRET) : null;
                    const refreshTokenValid: boolean = decodedOldRefreshToken ? await isRefreshTokenValid(this.config.redisClient, decodedOldRefreshToken.jti) : false;

                    if (decodedOldRefreshToken && refreshTokenValid) {
                        // If refresh token is valid and thus a userId can be extracted, regenerate both

                        // First, invalidate the current refresh token (AT is already invalid)
                        await setRefreshTokenInvalid(this.config.redisClient, decodedOldRefreshToken.jti)

                        // Then try to reauthenticate
                        user = await this.config.dbClient.getUserByUserId(decodedOldRefreshToken.sub);

                        // TODO: Check if user is not banned or something else, and throw an error in this case
                        const isUserBanned: boolean = user ? false : false;

                        if (!user || isUserBanned) {
                            // If user does not exist or has been banned,
                            // clear both cookies (refresh token cookie surely exists)
                            await clearAndInvalidateJwtTokens(this.config.redisClient, req, res, {
                                jwtSecret: this.config.SECRETS.JWT_SECRET,
                                ATCookieName: this.config.cookieConfig.ATCookieName,
                                ATExpiresInSeconds: this.config.cookieConfig.ATExpiresInSeconds,
                                RTCookieName: this.config.cookieConfig.RTCookieName
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
                        await setJwtTokensInCookies(this.config.redisClient, user, res, {
                            jwtSecret: this.config.SECRETS.JWT_SECRET,
                            ATCookieName: this.config.cookieConfig.ATCookieName,
                            RTCookieName: this.config.cookieConfig.RTCookieName,
                            ATExpiresInSeconds: this.config.cookieConfig.ATExpiresInSeconds,
                            RTExpiresInSeconds: this.config.cookieConfig.RTExpiresInSeconds
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
                    await clearAndInvalidateJwtTokens(this.config.redisClient, req, res, {
                        jwtSecret: this.config.SECRETS.JWT_SECRET,
                        ATCookieName: this.config.cookieConfig.ATCookieName,
                        RTCookieName: this.config.cookieConfig.RTCookieName,
                        ATExpiresInSeconds: this.config.cookieConfig.ATExpiresInSeconds
                    });
                }

                next();
            })(req, res, next);
        });

    }

    public withEmailPasswordAuth(): WebauthWizardryForExpress {
        // START Email / password
        // Basic authentication is not needed, it might be useful only when needing some automatic browser auth
        // https://stackoverflow.com/questions/8127635/why-should-i-use-http-basic-authentication-instead-of-username-and-password-post
        this.config.router.post('/signin',
            // Signin and signup must be called with no authentication
            assertNoAuthMiddleware(),
            async (req: ExtendedRequest, res: Response, next: ExtendedNextFunction) => {
                const { email, password } = req.body;

                if (!email || !password) {
                    next(new BadRequestError());
                    return;
                }

                try {
                    const user = await this.config.dbClient.getUserByEmailPassword(email, password);
                    if (!user) {
                        // Return a generic error
                        next(new UserNotFoundError());
                        return;
                    }

                    req.user = user;

                    next();
                }
                catch {
                    // Return a generic error
                    next(new UserNotFoundError());
                }
            }, setJwtTokensInCookieMiddleware(this.config.redisClient, {
                jwtSecret: this.config.SECRETS.JWT_SECRET,
                ATCookieName: this.config.cookieConfig.ATCookieName,
                RTCookieName: this.config.cookieConfig.RTCookieName,
                ATExpiresInSeconds: this.config.cookieConfig.ATExpiresInSeconds,
                RTExpiresInSeconds: this.config.cookieConfig.RTExpiresInSeconds
            })); // Call the middleware to generate and set the jwt token in cookies

        // Register a user
        this.config.router.post('/signup',
            // Signin and signup must be called with no authentication
            assertNoAuthMiddleware(),
            async (req: ExtendedRequest, res: Response, next: ExtendedNextFunction) => {
                const { email, password } = req.body;

                if (!email || !password) {
                    next(new BadRequestError());
                    return;
                }

                const user = await this.config.dbClient.createUserByEmailPassword(email, password);
                if (!user) {
                    // Return a generic error stating that the email address is not available for some reasons
                    // This has less information disclosure than an explicit "Email already taken"
                    next(new ExtendedError(400, "Email address not available"));
                    return;
                }

                req.user = user;
                next();

            }, setJwtTokensInCookieMiddleware(this.config.redisClient, {
                jwtSecret: this.config.SECRETS.JWT_SECRET,
                ATCookieName: this.config.cookieConfig.ATCookieName,
                RTCookieName: this.config.cookieConfig.RTCookieName,
                ATExpiresInSeconds: this.config.cookieConfig.ATExpiresInSeconds,
                RTExpiresInSeconds: this.config.cookieConfig.RTExpiresInSeconds
            })); // Call the middleware to generate and set the jwt token in cookies

        // END Email / password

        return this;
    }

    private setupLogout() {
        // Performs logout
        this.config.router.post('/logout',
            // Logout must be called with authentication
            assertAuthMiddleware(),
            clearAndInvalidateJwtTokensMiddleware(this.config.redisClient, {
                jwtSecret: this.config.SECRETS.JWT_SECRET,
                ATCookieName: this.config.cookieConfig.ATCookieName,
                RTCookieName: this.config.cookieConfig.RTCookieName,
                ATExpiresInSeconds: this.config.cookieConfig.ATExpiresInSeconds
            }), (req: ExtendedRequest, res: Response) => {
                // Jwt tokens have both been invalidated and removed from cookies

                res.status(200).send("OK");
            });
    }
}