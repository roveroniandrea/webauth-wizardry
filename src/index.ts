import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import express, { Request, Response } from 'express';
import passport from 'passport';
import CookieStrategy from 'passport-cookie';
import { assertAuth } from './auth/auth';
import { assertAuthMiddleware, clearAndInvalidateJwtTokensMiddleware, setJwtTokensInCookieMiddleware } from './auth/middlewares';
import { DummyDB } from './db/dummyDB';
import { AT_COOKIE_NAME, RT_COOKIE_NAME, clearAndInvalidateJwtTokens, decodeAccessToken, decodeRefreshToken, setJwtTokensInCookies } from './jwt/jwt';
import { initRedisClient, isAccessTokenValid, isRefreshTokenValid, setRefreshTokenInvalid } from './redis/redis';
import { ExtendedError, ExtendedNextFunction } from './types/error';
import { ExtendedRequest } from './types/extendedRequest';
import { User } from './types/user';

// Loading dotenv
dotenv.config();

const app = express();
const port = 3000;

// Body parser allows to populate `req.body`
app.use(bodyParser.json());

// A secret is required in order to create signed cookies
const COOKIE_PARSER_SECRET = process.env.COOKIE_PARSER_SECRET;
if (!COOKIE_PARSER_SECRET) {
    throw new Error("Missing configuration");
}
// CookieParser sets `req.cookies` and `req.signedCookies`
app.use(cookieParser(COOKIE_PARSER_SECRET));


// Passport strategies
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
    const accessTokenValid: boolean = decodedAccessToken ? await isAccessTokenValid(decodedAccessToken.jti) : false;

    // If access token is present and valid, return the user. Otherwise, access token will be cleared later
    done(null, (decodedAccessToken?.data && accessTokenValid) ? decodedAccessToken.data : null);
}));


// For every request, extract the jwt payload from the cookies and verify it
app.use((req: ExtendedRequest, res: Response, next: ExtendedNextFunction) => {

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
            const refreshTokenValid: boolean = decodedOldRefreshToken ? await isRefreshTokenValid(decodedOldRefreshToken.jti) : false;

            if (decodedOldRefreshToken && refreshTokenValid) {
                // If refresh token is valid and thus a userId can be extracted, regenerate both

                try {
                    user = await DummyDB.getUserByUserId(decodedOldRefreshToken.sub);
                    // TODO: Check if user is not banned or something else, and throw an error in this case

                    // If a new token has been generated, invalidate the current refresh token (AT is already invalid)
                    await setRefreshTokenInvalid(decodedOldRefreshToken.jti)
                }
                catch {
                    // If reaching here, refresh token was valid, but the user couldn't be reauthenticated for any reason

                    // Clear both cookies (refresh token cookie surely exists)
                    await clearAndInvalidateJwtTokens(req, res);

                    // NOTE: 400 should be the default error to tell FE that something is wrong and should re-authenticate
                    next(new ExtendedError(400, "Not authenticated"));
                    return;
                }
            }

            // Here, the user might have been reauthenticated via refresh token or might be totally unauthenticated because of no refresh token
            if (user) {
                // If authenticated, set new tokens in cookies
                await setJwtTokensInCookies(user, res);
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
            await clearAndInvalidateJwtTokens(req, res);
        }

        next();
    })(req, res, next);
});



// This route does not require authentication
app.get('/', (req, res) => {
    res.send('Hello World!');
});


// START Email / password
// Basic authentication is not needed, it might be useful only when needing some automatic browser auth
// https://stackoverflow.com/questions/8127635/why-should-i-use-http-basic-authentication-instead-of-username-and-password-post
// TODO: Signin and signup must be called with no authentication (use custom middleware) or invalidate existing tokens
app.post('/signin', async (req: ExtendedRequest, res, next: ExtendedNextFunction) => {
    const { email, password } = req.body;

    if (!email || !password) {
        next(new ExtendedError(400, "Missing required data"));
        return;
    }

    try {
        const user = await DummyDB.getUserByEmailPassword(email, password);
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
}, setJwtTokensInCookieMiddleware); // Call the middleware to generate and set the jwt token in cookies

// Register a user
// TODO: Signin and signup must be called with no authentication (use custom middleware) or invalidate existing tokens
app.post('/signup', async (req: ExtendedRequest, res, next: ExtendedNextFunction) => {
    const { email, password } = req.body;

    if (!email || !password) {
        next(new ExtendedError(400, "Missing required data"));
        return;
    }
    try {
        const user = await DummyDB.createUserByEmailPassword(email, password);
        if (!user) {
            // Return a generic error
            next(new ExtendedError(400, "Bad request"));
            return;
        }

        req.user = user;

        next();
    }
    catch {
        // Return a generic error
        next(new ExtendedError(400, "Bad request"));
    }
}, setJwtTokensInCookieMiddleware); // Call the middleware to generate and set the jwt token in cookies

// END Email / password


app.get('/users', async (_, res) => {
    const users: User[] = await DummyDB.listUsers();

    res.send(users);
});

// Retrieves info about the current logged user
// This endpoint requires authentication
// See also /me/middleware route
app.get('/me', (req, res) => {
    // `assertAuth` throws 401 if request is not authorized
    const user = assertAuth(req);

    res.send(user);
});


// Retrieves info about the current logged user but using a middleware
// This endpoint requires authentication
// See also /me route
app.get('/me/middleware', assertAuthMiddleware(), (req, res) => {
    res.send(req.user);
});


// Performs logout
app.post('/logout', assertAuthMiddleware(), clearAndInvalidateJwtTokensMiddleware, (req, res) => {
    // Jwt tokens have both been invalidated and removed from cookies

    res.status(200).send("OK");
});



// Catching errors
// This needs to be defined as last middleware to intercept everything
app.use((err: Error, req: ExtendedRequest, res: Response, next: ExtendedNextFunction): void => {
    if (err instanceof ExtendedError) {
        res.status(err.statusCode).send(err.message);
    }
    else {
        res.status(500).send("Internal Server Error");
    }
});


// Init redis client
initRedisClient()
    .then(() => {
        // Start listening
        app.listen(port, () => {
            console.log(`Server listening on port ${port}`);
        });
    })

