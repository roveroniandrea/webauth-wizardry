import { BaseClient, CallbackParamsType, IdTokenClaims, TokenSet, generators } from 'openid-client';
import { ExpressMiddleware, ExtendedRequest, ExtendedResponse } from '../types/express';
import { CookieOptions, NextFunction } from 'express';
import { ProviderData } from '../types/provider';
import { OpenIDProvidersConfig, WebauthWizardryConfig } from '../types/webauth-wizardry';
import { BadRequestError } from '../auth/errors';
import { ExtendedError } from '../types/error';
import { OpenIDUser, User } from '../types/user';


function calculateCookieNames(provider: ProviderData, openIdProvidersConfig: OpenIDProvidersConfig) {
    const calculatedStateCookieNameForProvider = `${openIdProvidersConfig.stateCookieName}-${provider.providerName}`;
    const calculatedNonceCookieNameForProvider = `${openIdProvidersConfig.nonceCookieName}-${provider.providerName}`;

    return {
        calculatedStateCookieNameForProvider: calculatedStateCookieNameForProvider,
        calculatedNonceCookieNameForProvider: calculatedNonceCookieNameForProvider
    }
}


export function openIdInitAuthenticationController(params: {
    provider: ProviderData;
    openIdProvidersConfig: OpenIDProvidersConfig;
    client: BaseClient;
    openIdCookieConfig: CookieOptions;
    buildRedirectUri: (req: ExtendedRequest, lastPath: string) => string;
}): ExpressMiddleware {
    return (req: ExtendedRequest, res: ExtendedResponse, next: NextFunction) => {

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
        const redirectUri = params.buildRedirectUri(req, `providers/${params.provider.providerName}/callback`);

        // This is the url to which redirect FE, and points to the provider's signin page (like Google "choose an account to login")
        const authUrl = params.client.authorizationUrl({
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
            max_age: params.openIdProvidersConfig.maxAgeTimeoutInSeconds
        });

        // Before redirecting, save both state and nonce in cookies

        const {
            calculatedStateCookieNameForProvider,
            calculatedNonceCookieNameForProvider
        } = calculateCookieNames(params.provider, params.openIdProvidersConfig);

        // The state is saved as a cookie
        res.cookie(calculatedStateCookieNameForProvider, requestState, params.openIdCookieConfig);

        // Same for nonce
        res.cookie(calculatedNonceCookieNameForProvider, requestNonce, params.openIdCookieConfig);

        // Finally, redirecting
        res.redirect(authUrl);
        next()
    }
}


export function openIdCallbackController(params: {
    provider: ProviderData;
    openIdProvidersConfig: OpenIDProvidersConfig;
    client: BaseClient;
    buildRedirectUri: (req: ExtendedRequest, lastPath: string) => string;
    config: WebauthWizardryConfig;
}): ExpressMiddleware {
    return async (req: ExtendedRequest, res: ExtendedResponse, next: NextFunction) => {

        const {
            calculatedStateCookieNameForProvider,
            calculatedNonceCookieNameForProvider
        } = calculateCookieNames(params.provider, params.openIdProvidersConfig);

        // First thing, in any case, unset both state and nonce cookie in the response
        // Cookies will still be available inside `req` object
        res.clearCookie(calculatedStateCookieNameForProvider);
        res.clearCookie(calculatedNonceCookieNameForProvider);

        // As said before, the request MUST have a state cookie
        const requestState: string = req.signedCookies[calculatedStateCookieNameForProvider];
        // The state in cookie MUST match the one passed to this GET request
        // (using callbackParams is just for parsing some query parameters)
        const callbackParams: CallbackParamsType = params.client.callbackParams(req);
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
            const redirectUri = params.buildRedirectUri(req, `providers/${params.provider.providerName}/callback`);

            // Now, exchage the "grant code" (which is one-time code)
            // whith a "token id"
            // Token ID is just an access token that contains user info on its payload
            // I do not think it gives access to anything else
            // See https://developers.google.com/identity/openid-connect/openid-connect?hl=it#obtainuserinfo
            const tokenSet: TokenSet = await params.client.callback(redirectUri, {
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
            const existingUserForProvider: OpenIDUser | null = await params.config.dbClient.getOpenIdUser(params.provider.providerName, tokenClaims.sub);

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
                const userDataByUserId: User | null = await params.config.dbClient.getUserByUserId(existingUserForProvider.userId);

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
                const userDataByEmail: User | null = await params.config.dbClient.getUserByEmail(tokenClaims.email);

                if (!userDataByEmail) {
                    // If match does not succeed, it means that this email was never used in this application
                    // So, create a new user, first on the "main" table
                    const newUser: User = await params.config.dbClient.createUserByEmail(tokenClaims.email);

                    // Then on the specific provider
                    await params.config.dbClient.createOpenIdUser({
                        userId: newUser.userId,
                        providerName: params.provider.providerName,
                        sub: tokenClaims.sub
                    });

                    // Proceed
                    req.user = newUser;
                }
                else {
                    // If match succeeds, it means that the user already has logged in with other methods
                    // Just create for this provider
                    await params.config.dbClient.createOpenIdUser({
                        userId: userDataByEmail.userId,
                        providerName: params.provider.providerName,
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
    }
}