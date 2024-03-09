import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import { CookieOptions, NextFunction } from 'express';
import { CallbackParamsType, IdTokenClaims, Issuer, TokenSet, generators } from 'openid-client';
import passport from 'passport';
import { BadRequestError, UserBannedError } from './auth/errors';
import { assertAuthMiddleware, assertNoAuthMiddleware, clearAndInvalidateJwtTokensMiddleware, setJwtTokensInCookieMiddleware } from './auth/middlewares';
import { EmailPwConfig, signInController } from './controllers/emailPasswordControllers';
import { clearAndInvalidateJwtTokens, decodeRefreshToken, setJwtTokensInCookies } from './jwt/jwt';
import { getAndDeleteEmailVerificationCode, isRefreshTokenValid, setRefreshTokenInvalid } from './redis/redis';
import { ExtendedError, ExtendedNextFunction } from './types/error';
import { ExpressMiddleware, ExtendedRequest, ExtendedResponse } from './types/express';
import { ProviderData } from './types/provider';
import { OpenIDUser, User } from './types/user';
import { OpenIDProvidersConfig, WebauthWizardryConfig } from './types/webauth-wizardry';
import { cookieAuthenticateCallback, cookieStrategy } from './strategies/cookieStrategy';
import { openIdCallbackController, openIdInitAuthenticationController } from './controllers/openIdControllers';

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

/** Config related to OpenID authentication */
const OPENID_PROVIDERS_CONFIG: OpenIDProvidersConfig = {
    /** State cookie when authenticating with an OpenID provider */
    stateCookieName: 'openId-state',
    /** Nonce cookie when authenticating with an OpenID provider */
    nonceCookieName: 'openId-nonce',
    /** Maximum elapsed time when authenticating with an OpenID provider */
    maxAgeTimeoutInSeconds: 60 * 2 // 2 minutes
}


export class WebauthWizardryForExpress {

    private readonly config: WebauthWizardryConfig;

    private get internalSetJwtTokensInCookieMiddleware(): ExpressMiddleware {
        return setJwtTokensInCookieMiddleware(this.config.redisClient, {
            jwtSecret: this.config.SECRETS.JWT_SECRET,
            ATCookieName: this.config.cookieConfig.ATCookieName,
            RTCookieName: this.config.cookieConfig.RTCookieName,
            ATExpiresInSeconds: this.config.cookieConfig.ATExpiresInSeconds,
            RTExpiresInSeconds: this.config.cookieConfig.RTExpiresInSeconds
        });
    }

    private get internalClearAndInvalidateJwtTokensMiddleware(): ExpressMiddleware {
        return clearAndInvalidateJwtTokensMiddleware(this.config.redisClient, {
            jwtSecret: this.config.SECRETS.JWT_SECRET,
            ATCookieName: this.config.cookieConfig.ATCookieName,
            RTCookieName: this.config.cookieConfig.RTCookieName,
            ATExpiresInSeconds: this.config.cookieConfig.ATExpiresInSeconds
        });
    }

    constructor(customConfig: Omit<WebauthWizardryConfig, "cookieConfig"> & {
        cookieConfig?: Partial<WebauthWizardryConfig["cookieConfig"]>;
    }) {
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

        // For every request, add some utility headers
        this.config.router.use((req: ExtendedRequest, res: ExtendedResponse, next: ExtendedNextFunction) => {
            // Allow credentials to be passed with "credentials: include" on cross domain request
            // TODO: Cross origin requests disabled
            // res.setHeader('Access-Control-Allow-Credentials', 'true');

            // Allow to pass and receive JSON data
            res.setHeader('Access-Control-Allow-Headers', ['Content-Type', 'Accept'])

            next();
        });

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


    /** Used to generate the callback urls to wich the OpenID provider will redirect */
    private buildRedirectUri(req: ExtendedRequest, lastPath: string): string {
        // This function had varius changes. Initially it used req.hostname, but that was wrong for two reasons:
        // - When allowing cors, this method assumed requests from same origin
        // - When removed and using a reverse proxy, this method assumed the internal host.docker.internal domain
        // The Host header can't be used due to reverse proxy, and same for Origin, not because it might be spoofed
        // (in that case it means the attacker would have just crafted a request with Postman or something, and signin would just fail)
        // but because it pointed to the FE
        // 
        // The easiest solution is to just provide a base url for how the server can be reached
        return `${this.config.serverConfig.serverBaseUrl}/${lastPath}`;
    }


    private setupCookieStrategy() {
        // Cookie strategy allows to extract token from cookies
        passport.use(cookieStrategy(this.config));

        // For every request, extract the jwt payload from the cookies and verify it
        this.config.router.use((req: ExtendedRequest, res: ExtendedResponse, next: ExtendedNextFunction) => {
            /*
        
                A custom callback is passed in order to allow two things:
                1 - For an unauthenticated request, check if user can be refreshed via refresh token (checking user validity to be reauthenticated, like for example user not banned)
                2 - Unauthenticated requests can proceed (except for refresh token banned)
        
                This is because some endpoints might not require authentication
        
            */
            passport.authenticate("cookie", { session: false }, cookieAuthenticateCallback(this.config, req, res, next));
        });
    }


    /** 
     * Provides email/pw authentication, along with email verification.
     * This requires to send emails
     */
    public withEmailPasswordAuth(emailPwConfig: EmailPwConfig): WebauthWizardryForExpress {
        // Basic authentication is not needed, it might be useful only when needing some automatic browser auth
        // https://stackoverflow.com/questions/8127635/why-should-i-use-http-basic-authentication-instead-of-username-and-password-post
        this.config.router.post('/signin',
            // Signin and signup must be called with no authentication
            assertNoAuthMiddleware(),
            // Call the controller
            signInController(this.config),
            // Call the middleware to generate and set the jwt token in cookies
            this.internalSetJwtTokensInCookieMiddleware,
            // Then, OK
            (req: ExtendedRequest, res: ExtendedResponse, next: ExtendedNextFunction) => {
                res.status(200).send({
                    error: null,
                    data: null
                });

                next();
            }); // Call the middleware to generate and set the jwt token in cookies

        // Register a user
        this.config.router.post('/signup',
            // Signin and signup must be called with no authentication
            assertNoAuthMiddleware(),

        );


        // Register a POST route for email verification
        // This MUST not be a GET, before email browsers or antivirus might perform a GET request to the verifiation link, and
        // that action must not confirm the email address as it would be a security flaw
        // Instead, the user must perform this POST request maybe pressing a button or something similar
        this.config.router.post('/email/verification',
            // To prevent confusing behaviour about "Am I authenticated now or not?"
            // Clear any previously authenticated user, but still require manual authentication even if this call succeeds
            this.internalClearAndInvalidateJwtTokensMiddleware,
            async (req: ExtendedRequest, res: ExtendedResponse, next: NextFunction) => {

                const verificationCode: string | null = req.body.verificationCode;
                // Retrieve and immediately invalidate the verification code
                const verificationData = verificationCode ? await getAndDeleteEmailVerificationCode(this.config.redisClient, verificationCode) : null;

                if (!verificationData) {
                    // If the verification code does not exist, end here
                    next(new ExtendedError(401, "Invalid verification code"));
                    return;
                }

                // Else, depends on what action needs to be performed
                try {
                    if (verificationData.mustMergeUser) {
                        // Here, user must be merged.
                        // It's the case when `userWithSameEmail` exists
                        await this.config.dbClient.createPasswordForUser(verificationData.userIdToMerge, verificationData.hashedPw);
                    }
                    else {
                        // Otherwise a new user must be created
                        const newUser: User = await this.config.dbClient.createUserByEmail(verificationData.email);

                        await this.config.dbClient.createPasswordForUser(newUser.userId, verificationData.hashedPw);
                    }
                }
                catch (ex) {
                    // Process might fail if during the meantime (from code generation and email verification)
                    // something has changed with the registered email (maybe user deleted when previously existed, or vice versa)
                    console.error(ex);
                    next(new ExtendedError(500, "Cannot verify email"));
                    return;
                }


                // Operation succeeded, but do not authenticate anything, require a manual authentication to prevent confusing behavior to the user
                res.status(200).send({
                    error: null,
                    data: null
                });
                next();
            });


        return this;
    }


    /**
     * Configures OpenId providers
     */
    public withOpenIdProviders(providers: ProviderData[], openIdProvidersConfigPartial: Partial<OpenIDProvidersConfig>): WebauthWizardryForExpress {

        // Merge config with default one
        const openIdProvidersConfig: OpenIDProvidersConfig = {
            ...OPENID_PROVIDERS_CONFIG,
            ...(openIdProvidersConfigPartial)
        }

        /** Calculated config for state and nonce cookies for the OpenID authentication */
        const openIdCookieConfig: CookieOptions = {
            // Setting expiration in milliseconds
            expires: undefined,
            maxAge: openIdProvidersConfig.maxAgeTimeoutInSeconds * 1000,
            // Not available to JS
            httpOnly: true,
            // Sent only for same origin request and when navigating from another origin
            // This is needed just for this cookies because the openId provider does a redirect, so strict would not work
            sameSite: "lax",
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

            //
            // Two endpoints need to be configured:
            //


            // 1- The GET endpoint for the client to request sign in with this provider
            // This will redirect the FE to google (for example, but it's valid for other OpenID providers) sign in
            // Later, Google will redirect to a GET callback url (the second endpoint)
            // See https://developers.google.com/identity/openid-connect/openid-connect?hl=it#sendauthrequest
            this.config.router.post(`/providers/${provider.providerName}`,
                assertNoAuthMiddleware(),
                openIdInitAuthenticationController({
                    client: client,
                    provider: provider,
                    openIdCookieConfig: openIdCookieConfig,
                    openIdProvidersConfig: openIdProvidersConfig,
                    buildRedirectUri: this.buildRedirectUri
                })
            );



            // 2- The callback endpoint, the one that the provider redirects to when the user has signed in
            // This callback has some query parameters in it
            // See https://developers.google.com/identity/openid-connect/openid-connect?hl=it#confirmxsrftoken
            this.config.router.get(`/providers/${provider.providerName}/callback`,
                assertNoAuthMiddleware(),
                openIdCallbackController({
                    client: client,
                    provider: provider,
                    openIdProvidersConfig: openIdProvidersConfig,
                    buildRedirectUri: this.buildRedirectUri,
                    config: this.config
                }),
                // The next handler will take care of extracting `req.user` and generate AT and RT tokens
                this.internalSetJwtTokensInCookieMiddleware,
                // Then, redirect to homepage
                (req: ExtendedRequest, res: ExtendedResponse, next: ExtendedNextFunction) => {
                    // TODO: Check if redirect is done to homepage
                    res.redirect('/');

                    next();
                });
        }

        return this;
    }


    private setupLogout() {
        // Performs logout
        this.config.router.post('/logout',
            // Logout must be called with authentication
            assertAuthMiddleware(),
            this.internalClearAndInvalidateJwtTokensMiddleware,
            (req: ExtendedRequest, res: ExtendedResponse) => {
                // Jwt tokens have both been invalidated and removed from cookies

                res.status(200).send({
                    error: null,
                    data: null
                });
            });
    }
}