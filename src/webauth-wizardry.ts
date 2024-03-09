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

            const calculatedStateCookieNameForProvider = `${openIdProvidersConfig.stateCookieName}-${provider.providerName}`;
            const calculatedNonceCookieNameForProvider = `${openIdProvidersConfig.nonceCookieName}-${provider.providerName}`;


            //
            // Two endpoints need to be configured:
            //


            // 1- The GET endpoint for the client to request sign in with this provider
            // This will redirect the FE to google (for example, but it's valid for other OpenID providers) sign in
            // Later, Google will redirect to a GET callback url (the second endpoint)
            // See https://developers.google.com/identity/openid-connect/openid-connect?hl=it#sendauthrequest
            this.config.router.post(`/providers/${provider.providerName}`, assertNoAuthMiddleware(), (req: ExtendedRequest, res: ExtendedResponse, next: NextFunction) => {

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
                const redirectUri = this.buildRedirectUri(req, `providers/${provider.providerName}/callback`);

                // This is the url to which redirect FE, and points to the provider's signin page (like Google "choose an account to login")
                const authUrl = client.authorizationUrl({
                    // Scope says "give me a grant code that I can use to obtain the following infos", and for requesting an id token, this means specifying which infos retrieve about the user 
                    // "openid" scope is always required
                    // "email" scope requests access to the email and email_verified Claims
                    // "profie" requests access to the End-User's default profile Claims, which are: name, family_name, given_name, middle_name, nickname, preferred_username, profile, picture, website, gender, birthdate, zoneinfo, locale, and updated_at
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
            this.config.router.get(`/providers/${provider.providerName}/callback`, assertNoAuthMiddleware(), async (req: ExtendedRequest, res: ExtendedResponse, next: NextFunction) => {

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
                    const redirectUri = this.buildRedirectUri(req, `providers/${provider.providerName}/callback`);

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
                        // OpenID specifies that if max_age is passed as claim on the auth request, an auth_time clain MUST be returned in jwy payload
                        // This seems not to happen for Google, so for now do not check max_age, otherwise passport will throw an
                        // RPError: missing required JWT property auth_time
                        max_age: undefined
                    });

                    // When token is retrieved (refresh token is not present)
                    // We can extract the user's data
                    const tokenClaims: IdTokenClaims = tokenSet.claims();

                    if (!tokenClaims.email || !tokenClaims.email_verified) {
                        // This check is important: the user MUST have its email verified on OpenID provider.
                        // Otherwise, an attacker could just create an account on that provider using the victim's email, not verifing the email,
                        // and authenticate as the victim account

                        // The "email verified" claim is surely presetn because it's requested by "email" scope

                        // Return a more clear error
                        next(new ExtendedError(401, "Email not verified on OpenID provider"));
                        return;
                    }

                    // Here the user can be merged, because its email is verified and can be trusted
                    const existingUserForProvider: OpenIDUser | null = await this.config.dbClient.getOpenIdUser(provider.providerName, tokenClaims.sub);

                    if (existingUserForProvider) {
                        // If user already exist, assert that the email has not changed
                        // This is because of the following problems:
                        //
                        // What happens if a user changes his email on a provider and then logs in with that provider?
                        // Will it still be logged in as the same user? What would happens to his data, like the email or other infos?
                        // The easiest solution is to refuse to handle a user that has changed his email.
                        // This will prevent any kind of problem like "wait, why the application still shows my old email?"
                        // or "Why my email keeps changing? (he's logging in with different providers each time)"
                        // Returning an error is the cleanest solution to solve this. In any case, users seldom change their email on providers
                        //
                        // This of course applies for all other user infos (profile picture, username etc)
                        // But it has less impact and probably it should be more useful to separate completely from openId
                        const userDataByUserId: User | null = await this.config.dbClient.getUserByUserId(existingUserForProvider.userId);

                        if (!userDataByUserId || userDataByUserId.email !== tokenClaims.email) {
                            // Return an error
                            next(new ExtendedError(401, "Email on OpenID provider has changed"));
                            return;
                        }

                        // Otherwise, proceed
                        req.user = userDataByUserId;

                    }
                    else {
                        // If the user does not exist with this specific provers, it might still exist because it has signed in with other methods
                        // Match is done via email, and this is another reason to forbid email changes on OpenID providers
                        // (well, more or less, match might still be valid when using a provider for the first time)
                        const userDataByEmail: User | null = await this.config.dbClient.getUserByEmail(tokenClaims.email);

                        if (!userDataByEmail) {
                            // If match does not succeed, it means that this email was never used in this application
                            // So, create a new user, first on the "main" table
                            const newUser: User = await this.config.dbClient.createUserByEmail(tokenClaims.email);

                            // Then on the specific provider
                            await this.config.dbClient.createOpenIdUser({
                                userId: newUser.userId,
                                providerName: provider.providerName,
                                sub: tokenClaims.sub
                            });

                            // Proceed
                            req.user = newUser;
                        }
                        else {
                            // If match succeeds, it means that the user already has logged in with other methods
                            // Just create for this provider
                            await this.config.dbClient.createOpenIdUser({
                                userId: userDataByEmail.userId,
                                providerName: provider.providerName,
                                sub: tokenClaims.sub
                            });

                            // Proceed
                            req.user = userDataByEmail;
                        }
                    }

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