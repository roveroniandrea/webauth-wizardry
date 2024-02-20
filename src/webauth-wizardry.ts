import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import { CookieOptions, NextFunction, Response, Router } from 'express';
import { CallbackParamsType, IdTokenClaims, Issuer, TokenSet, generators } from 'openid-client';
import passport from 'passport';
import CookieStrategy from 'passport-cookie';
import { RedisClientType } from 'redis';
import { BadRequestError, UserBannedError, UserNotFoundError } from './auth/errors';
import { assertAuthMiddleware, assertNoAuthMiddleware, clearAndInvalidateJwtTokensMiddleware, setJwtTokensInCookieMiddleware } from './auth/middlewares';
import { DatabaseInterface } from './db/databaseInterface';
import { clearAndInvalidateJwtTokens, decodeAccessToken, decodeRefreshToken, setJwtTokensInCookies } from './jwt/jwt';
import { isAccessTokenValid, isRefreshTokenValid, setRefreshTokenInvalid } from './redis/redis';
import { ExtendedError, ExtendedNextFunction } from './types/error';
import { ExtendedRequest } from './types/express';
import { ProviderData } from './types/provider';
import { User } from './types/user';

/** Config related to auth tokens and cookies */
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

type OpenIDProvidersConfig = {
    serverPort: number | null;
    routerPath: string;
    stateCookieName: string;
    nonceCookieName: string;
    maxAgeTimeoutInSeconds: number;
}

/** Config related to OpenID authentication */
const OPENID_PROVIDERS_CONFIG: OpenIDProvidersConfig = {
    serverPort: null,
    routerPath: '/',
    /** State cookie when authenticating with an OpenID provider */
    stateCookieName: 'openId-state',
    /** Nonce cookie when authenticating with an OpenID provider */
    nonceCookieName: 'openId-nonce',
    /** Maximum elapsed time when authenticating with an OpenID provider */
    maxAgeTimeoutInSeconds: 60 * 2 // 2 minutes
}

export class WebauthWizardryForExpress {

    private readonly config: Omit<WebauthWizardryConfig, "cookieConfig"> & {
        cookieConfig: typeof DEFAULT_COOKIE_CONFIG;
    };

    private get internalSetJwtTokensInCookieMiddleware() {
        return setJwtTokensInCookieMiddleware(this.config.redisClient, {
            jwtSecret: this.config.SECRETS.JWT_SECRET,
            ATCookieName: this.config.cookieConfig.ATCookieName,
            RTCookieName: this.config.cookieConfig.RTCookieName,
            ATExpiresInSeconds: this.config.cookieConfig.ATExpiresInSeconds,
            RTExpiresInSeconds: this.config.cookieConfig.RTExpiresInSeconds
        });
    }

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
            }, this.internalSetJwtTokensInCookieMiddleware); // Call the middleware to generate and set the jwt token in cookies

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

                // TODO: This needs to merge a user rather that creating
                // FIXME: what if the user already exists because it has signed in with an OpenID provider?
                // Letting an email/password to merge an already existing user would allow anyone to set a custom pw and authenticate as a user registered with openId
                const user = await this.config.dbClient.createUserByEmailPassword(email, password);
                if (!user) {
                    // Return a generic error stating that the email address is not available for some reasons
                    // This has less information disclosure than an explicit "Email already taken"
                    next(new ExtendedError(400, "Email address not available"));
                    return;
                }

                req.user = user;
                next();

            }, this.internalSetJwtTokensInCookieMiddleware); // Call the middleware to generate and set the jwt token in cookies

        // END Email / password

        return this;
    }


    /**
     * Configures OpenId providers
     */
    public withOpenIdProviders(providers: ProviderData[], openIdProvidersConfigPartial: Partial<OpenIDProvidersConfig>): WebauthWizardryForExpress {

        // Merge config with default one
        const openIdProvidersConfig: OpenIDProvidersConfig = {
            ...(openIdProvidersConfigPartial),
            ...OPENID_PROVIDERS_CONFIG
        }

        /** Calculated config for state and nonce cookies for the OpenID authentication */
        const openIdCookieConfig: CookieOptions = {
            // Setting expiration in milliseconds
            expires: undefined,
            maxAge: openIdProvidersConfig.maxAgeTimeoutInSeconds * 1000,
            // Not available to JS
            httpOnly: true,
            // Sent only to this domain
            sameSite: "strict",
            // Available only in https
            secure: true,
            // Cookie is signed to ensure client does not modify it
            signed: true
        }

        for (const provider of providers) {
            if (!provider.providerName || !provider.clientSecret || !provider.clientId) {
                throw new Error(`Missing configuration for provider ${provider.providerName}`)
            }

            const issuer = new Issuer(provider.issuerMetadata);

            const client = new issuer.Client({
                client_id: provider.clientId,
                client_secret: provider.clientSecret
            });

            /** Used to generate the callback urls to wich the OpenID provider will redirect */
            const buildRedirectUri = (req: ExtendedRequest, lastPath: string) => {
                return `${req.protocol}://${req.hostname}${openIdProvidersConfig.serverPort ? `:${openIdProvidersConfig.serverPort}` : ""}${openIdProvidersConfig.routerPath}providers/${provider.providerName}/${lastPath}`;
            }

            const calculatedStateCookieNameForProvider = `${openIdProvidersConfig.stateCookieName}-${provider.providerName}`;
            const calculatedNonceCookieNameForProvider = `${openIdProvidersConfig.nonceCookieName}-${provider.providerName}`;


            //
            // Two endpoints need to be configured:
            //


            // 1- The GET endpoint for the client to request sign in with this provider
            // This will redirect the FE to google (for example, but it's valid for other OpenID providers) sign in
            // Later, Google will redirect to a GET callback url (the second endpoint)
            // See https://developers.google.com/identity/openid-connect/openid-connect?hl=it#sendauthrequest
            this.config.router.post(`/providers/${provider.providerName}`, assertNoAuthMiddleware(), (req: ExtendedRequest, res: Response, next: NextFunction) => {

                // Documentation on https://www.passportjs.org/packages/openid-client/ is not examctly what I need here, because
                // when authenticating with google, it says that code_verified (used in documentation) is not required for this "message type" (I think response type)
                // Instead, nonce is required
                // I think this is because no resource access is requested here?


                // To ensure all those redirects etc can betrusted, two checks need to be performed on the next calls
                // Request should have a state: this state is passed to Google, and Google must pass the same state at the callback
                // See https://developers.google.com/identity/openid-connect/openid-connect?hl=it#createxsrftoken
                const requestState = generators.state();
                // Nonce should be checked later that state, when exchanging the granted code with user tokenId
                const requestNonce = generators.nonce();


                // This is the url that Google will redirect after the user has authenticated on its page
                const redirectUri = buildRedirectUri(req, "callback");

                // This is the url to which redirect FE, and points to the provider's signin page (like Google "choose an account to login")
                const authUrl = client.authorizationUrl({
                    // Scope says "give me a grant code that I can use to obtain the following infos"
                    scope: "openid email profile",
                    // Response type "code" tells the OpenID provider to initiate a "Server flow" aka "Base flow" aka "Authorization code flow"
                    // This flow is the one used for web servers (not clients)
                    // For autheticating a client without BE, an "implicit flow" is needed
                    // See https://developers.google.com/identity/openid-connect/openid-connect?hl=it#authenticatingtheuser
                    response_type: "code",
                    // Callback endpoint
                    redirect_uri: redirectUri,
                    // State and nonces needs to be checked later
                    state: requestState,
                    nonce: requestNonce,
                    // Set a maximum login timeout
                    // Max age is in seconds for OpenID
                    max_age: openIdProvidersConfig.maxAgeTimeoutInSeconds
                });

                // Before redirecting, save both state and nonce in cookies

                // The state is saved as a cookie
                res.cookie(calculatedStateCookieNameForProvider, requestState, openIdCookieConfig);

                // Same for nonce
                res.cookie(calculatedNonceCookieNameForProvider, requestNonce, openIdCookieConfig);

                // Finally, redirecting
                res.redirect(authUrl);
                next()
            });



            // 2- The callback endpoint, the one that the provider redirects to when the user has signed in
            // This callback has some query parameters in it
            // See https://developers.google.com/identity/openid-connect/openid-connect?hl=it#confirmxsrftoken
            this.config.router.get(`/providers/${provider.providerName}/callback`, assertNoAuthMiddleware(), async (req: ExtendedRequest, res: Response, next: NextFunction) => {

                // First thing, in any case, unset both state and nonce cookie in the response
                // Cookies will still be available inside `req` object
                res.clearCookie(calculatedStateCookieNameForProvider);
                res.clearCookie(calculatedNonceCookieNameForProvider);

                // As said before, the request MUST have a state cookie
                const requestState: string = req.signedCookies[calculatedStateCookieNameForProvider];
                // The state in cookie MUST match the one passed to this GET request
                // (using callbackParams is just for parsing some query parameters)
                const callbackParams: CallbackParamsType = client.callbackParams(req);
                if (!requestState || !callbackParams.state || requestState !== callbackParams.state) {
                    next(new BadRequestError());
                    return;
                }

                try {
                    // Same check needs to be done with nonce
                    const requestNonce: string = req.signedCookies[calculatedNonceCookieNameForProvider];
                    if (!requestNonce) {
                        next(new BadRequestError());
                        return;
                    }

                    // This redirect uri is not called again
                    // I think this is likely a third check, along with state and nonce, but this time performed by the OpenID provider
                    // in fact, passing a different uri, even if allowed in oauth configuration (on google cloud console for example)
                    // gives Uncaught OPError OPError: redirect_uri_mismatch
                    const redirectUri = buildRedirectUri(req, "callback");

                    // Now, exchage the "grant code" (which is one-time code)
                    // whith a "token id"
                    // Token ID is just an access token that contains user info on its payload
                    // I do not think it gives access to anything else
                    // See https://developers.google.com/identity/openid-connect/openid-connect?hl=it#obtainuserinfo
                    const tokenSet: TokenSet = await client.callback(redirectUri, {
                        // The grant code is the ont-time code that the provider has passed to this callback endpoint,
                        // And its purpose is to retrieve some other token
                        code: callbackParams.code
                    }, {
                        // This time, nonce is verified internally by the passport strategy
                        nonce: requestNonce,
                        // Also check max age
                        max_age: openIdProvidersConfig.maxAgeTimeoutInSeconds
                    });

                    // When token is retrieved (refresh token is not present)
                    // We can extract the user's data
                    const user: IdTokenClaims = tokenSet.claims();

                    if (!user.email_verified) {
                        // This check is important: the user MUST have its email verified on OpenID provider.
                        // Otherwise, an attacker could just create an account on that provider using the victim's email, not verifing the email,
                        // and authenticate as the victim account

                        // Return a more clear error
                        next(new ExtendedError(401, "Email not verified on OpenID provider"));
                        return;
                    }

                    // Here the user can be merged, because its email is verified and can be trusted
                    // TODO: Merge user and set req.user

                    // State and nonce cookies have already been cleared
                    next();
                }
                catch (ex) {
                    // `client.callback` might throw an error if nonce verification fails
                    // To prevent the process from exiting, catch it and return an error
                    console.error(ex);
                    next(new BadRequestError());
                }
            },
                // The next handler will take care of extracting `req.user` and generate AT and RT tokens
                this.internalSetJwtTokensInCookieMiddleware);
        }

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