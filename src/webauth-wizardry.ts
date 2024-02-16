import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import { Response, Router } from 'express';
import passport from 'passport';
import CookieStrategy from 'passport-cookie';
import { RedisClientType } from 'redis';
import { assertAuthMiddleware, assertNoAuthMiddleware, clearAndInvalidateJwtTokensMiddleware, setJwtTokensInCookieMiddleware } from './auth/middlewares';
import { DatabaseInterface } from './db/databaseInterface';
import { AT_COOKIE_NAME, RT_COOKIE_NAME, clearAndInvalidateJwtTokens, decodeAccessToken, decodeRefreshToken, setJwtTokensInCookies } from './jwt/jwt';
import { isAccessTokenValid, isRefreshTokenValid, setRefreshTokenInvalid } from './redis/redis';
import { ExtendedError, ExtendedNextFunction } from './types/error';
import { ExtendedRequest } from './types/express';
import { User } from './types/user';

type WebauthWizardryConfig = {
    router: Router;
    redisClient: RedisClientType;
    dbClient: DatabaseInterface;
}

export class WebauthWizardryForExpress {
    constructor(private readonly config: WebauthWizardryConfig) {
        // Body parser allows to populate `req.body`
        config.router.use(bodyParser.json());

        // A secret is required in order to create signed cookies
        const COOKIE_PARSER_SECRET = process.env.COOKIE_PARSER_SECRET;
        if (!COOKIE_PARSER_SECRET) {
            throw new Error("Missing configuration");
        }
        // CookieParser sets `req.cookies` and `req.signedCookies`
        config.router.use(cookieParser(COOKIE_PARSER_SECRET));

        // Passport strategies
        this.setupCookieStrategy();

        // Always setup logout route
        this.setupLogout();
    }

    private setupCookieStrategy() {
        // Cookie strategy allows to extract token from cookies
        passport.use(new CookieStrategy({
            cookieName: AT_COOKIE_NAME,
            signed: true,
            passReqToCallback: true
        }, async (req: Request, token: string, done: (err: ExtendedError | null, user: User | null) => void) => {
            // If there's a token, decode and extract it
            // This will never throw an error, just null in case the user cannot be extracted for any reason
            const decodedAccessToken = await decodeAccessToken(token);

            // Also, check access token validity
            const accessTokenValid: boolean = decodedAccessToken ? await isAccessTokenValid(this.config.redisClient, decodedAccessToken.jti) : false;

            // If access token is present and valid, return the user. Otherwise, access token will be cleared later
            done(null, (decodedAccessToken?.data && accessTokenValid) ? decodedAccessToken.data : null);
        }));


        // For every request, extract the jwt payload from the cookies and verify it
        this.config.router.use((req: ExtendedRequest, res: Response, next: ExtendedNextFunction) => {

            /*
        
                A custom callback is passed in order to allow two things:
                1 - For an unauthenticated request, check if user can be refreshed via refresh token (checking user validity to be reauthenticated, like for example user not banned)
                2 - Unauthenticated requests can proceed (except for refresh token banned)
        
                This is because some endpoints might not require authentication
        
            */
            passport.authenticate("cookie", { session: false }, async (err: any, user: User | false, info: any, status: any) => {
                // If there's an error, throw it
                if (err) {
                    next(err);
                    return;
                }

                // For unauthenticated requests (meaning the user cannot be recovered from access token) `user` will be at `false`
                // TODO: This might be converted into a custom strategy or middleware?
                if (!user) {
                    // If for any reason the user cannot be extracted from access token (missing cookie, jwt invalid), try refreshing the session
                    const oldRefreshToken: string = req.signedCookies[RT_COOKIE_NAME];

                    // Decode the extracted refresh token and check its validity
                    const decodedOldRefreshToken = oldRefreshToken ? await decodeRefreshToken(oldRefreshToken) : null;
                    const refreshTokenValid: boolean = decodedOldRefreshToken ? await isRefreshTokenValid(this.config.redisClient, decodedOldRefreshToken.jti) : false;

                    if (decodedOldRefreshToken && refreshTokenValid) {
                        // If refresh token is valid and thus a userId can be extracted, regenerate both

                        try {
                            user = await this.config.dbClient.getUserByUserId(decodedOldRefreshToken.sub);
                            // TODO: Check if user is not banned or something else, and throw an error in this case

                            // If a new token has been generated, invalidate the current refresh token (AT is already invalid)
                            await setRefreshTokenInvalid(this.config.redisClient, decodedOldRefreshToken.jti)
                        }
                        catch {
                            // If reaching here, refresh token was valid, but the user couldn't be reauthenticated for any reason

                            // Clear both cookies (refresh token cookie surely exists)
                            await clearAndInvalidateJwtTokens(this.config.redisClient, req, res);

                            // NOTE: 400 should be the default error to tell FE that something is wrong and should re-authenticate
                            next(new ExtendedError(400, "Not authenticated"));
                            return;
                        }
                    }

                    // Here, the user might have been reauthenticated via refresh token or might be totally unauthenticated because of no refresh token
                    if (user) {
                        // If authenticated, set new tokens in cookies
                        await setJwtTokensInCookies(this.config.redisClient, user, res);
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
                    await clearAndInvalidateJwtTokens(this.config.redisClient, req, res);
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
                    next(new ExtendedError(400, "Missing required data"));
                    return;
                }

                try {
                    const user = await this.config.dbClient.getUserByEmailPassword(email, password);
                    if (!user) {
                        // Return a generic error
                        next(new ExtendedError(404, "User not found"));
                        return;
                    }

                    req.user = user;

                    next();
                }
                catch {
                    // Return a generic error
                    next(new ExtendedError(404, "User not found"));
                }
            }, setJwtTokensInCookieMiddleware(this.config.redisClient)); // Call the middleware to generate and set the jwt token in cookies

        // Register a user
        this.config.router.post('/signup',
            // Signin and signup must be called with no authentication
            assertNoAuthMiddleware(),
            async (req: ExtendedRequest, res: Response, next: ExtendedNextFunction) => {
                const { email, password } = req.body;

                if (!email || !password) {
                    next(new ExtendedError(400, "Missing required data"));
                    return;
                }
                try {
                    const user = await this.config.dbClient.createUserByEmailPassword(email, password);
                    if (!user) {
                        // Return a generic error
                        next(new ExtendedError(400, "Email address not available"));
                        return;
                    }

                    req.user = user;

                    next();
                }
                catch {
                    // Return a generic error
                    next(new ExtendedError(400, "Bad request"));
                }
            }, setJwtTokensInCookieMiddleware(this.config.redisClient)); // Call the middleware to generate and set the jwt token in cookies

        // END Email / password

        return this;
    }

    private setupLogout() {
        // Performs logout
        this.config.router.post('/logout',
            // Logout must be called with authentication
            assertAuthMiddleware(),
            clearAndInvalidateJwtTokensMiddleware(this.config.redisClient), (req: ExtendedRequest, res: Response) => {
                // Jwt tokens have both been invalidated and removed from cookies

                res.status(200).send("OK");
            });
    }
}