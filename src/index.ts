import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import express, { Request, Response } from 'express';
import passport from 'passport';
import CookieStrategy from 'passport-cookie';
import { assertAuth } from './auth/auth';
import { DummyDB } from './db/dummyDB';
import { AT_COOKIE_NAME, RT_COOKIE_NAME, decodeAccessToken, decodeRefreshToken, setJwtTokenInCookie } from './jwt/jwt';
import { ExtendedError, ExtendedNextFunction } from './types/error';
import { ExtendedRequest } from './types/extendedRequest';
import { User } from './types/user';
import { assertAuthMiddleware, setJwtTokenInCookieMiddleware } from './auth/middlewares';

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
    const user = await decodeAccessToken(token);

    done(null, user);
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
            // If for any reason the user cannot be extracted from access token (missing cookie, jwt invalid)
            // try refreshing the session
            const refreshToken: string = req.signedCookies[RT_COOKIE_NAME];

            const userId = refreshToken ? await decodeRefreshToken(refreshToken) : null;

            if (userId) {
                // If refresh token is valid and thus a userId can be extracted, regenerate both
                // TODO: It's needed to invalidate this refresh token here
                // TODO: Also, refresh token validity must be checked in this step

                try {
                    user = await DummyDB.getUserByUserId(userId);
                }
                catch { }

                // TODO: Check if user is not banned or something else
                if (!user || !req.res) {
                    // The only code that will return an error is here
                    // This is because user cannot be reauthenticated with its refresh token for some reason
                    // So clear both cookies in any way

                    // NOTE: 400 should be the default error to tell FE that something is wrong and should re-authenticate
                    req.res?.clearCookie(AT_COOKIE_NAME);
                    req.res?.clearCookie(RT_COOKIE_NAME);
                    next(new ExtendedError(400, "Not authenticated"));
                    return;
                }
                else {
                    // Otherwise, set new tokens as cookies
                    await setJwtTokenInCookie(user, res);
                }
            }

            // Here, the user might have been reauthenticated via refresh token or might be totally unauthenticated
            if (!user) {
                // if user is not authenticated, clear both cookies in any way
                req.res?.clearCookie(AT_COOKIE_NAME);
                req.res?.clearCookie(RT_COOKIE_NAME);
            }
        }

        // At this point, if AT was valid, request is authenticated
        // Otherwise, depends on RT:
        //      If RT was valid, both tokens have been regenerated and set as cookies
        //      If RT was not valid or user was banned, both tokens have been cleared

        // Proceed with or without the user
        req.user = user || undefined;

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
// TODO: Signin and signup must be called with no authentication (use custom middleware)
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
}, setJwtTokenInCookieMiddleware); // Call the middleware to generate and set the jwt token in cookies

// Register a user
// TODO: Signin and signup must be called with no authentication (use custom middleware)
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
}, setJwtTokenInCookieMiddleware); // Call the middleware to generate and set the jwt token in cookies

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


// Start listening
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
