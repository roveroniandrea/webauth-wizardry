import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import express, { Request, Response } from 'express';
import passport from 'passport';
import CookieStrategy from 'passport-cookie';
import { assertAuth } from './auth/auth';
import { DummyDB } from './db/dummyDB';
import { JWT_COOKIE_NAME, assertDecodeToken, setJwtTokenInCookieMiddleware } from './jwt/jwt';
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
    cookieName: JWT_COOKIE_NAME,
    signed: true,
    passReqToCallback: true
}, async (req: Request, token: string, done: (err: ExtendedError | null, user: User | null) => void) => {
    try {
        if (token) {
            // If there's a token, decode and extract it
            // This will throw an error if the token is not valid
            const user = await assertDecodeToken(token);

            // TODO: Check for banning or something else

            done(null, user);
        }
        else {
            // Otherwise no problem, request is not authenticated
            done(null, null);
        }
    }
    catch (ex) {
        // This point is reached if the token is invalid in some way
        // So clear the cookie in any way

        // NOTE: 400 should be the default error to tell FE that something is wrong and should re-authenticate
        req.res?.clearCookie(JWT_COOKIE_NAME);
        done(new ExtendedError(400, "Not authenticated"), null);
    }
}));


// For every request, extract the jwt payload from the cookies and verify it
app.use((req: ExtendedRequest, res: Response, next: ExtendedNextFunction) => {
    // A custom callback is passed in order to allow even unauthenticated request to proceed
    // This is because some endpoints might not require authentication
    passport.authenticate("cookie", { session: false }, (err: any, user: User, info: any, status: any) => {
        // If there's an error, throw it
        if (err) {
            next(err);
            return;
        }

        // For unauthenticated requests (meaning the cookie is absent, not that the token is invalid)
        // Will have `user` at false, override it to null
        req.user = user || null;
        // Proceed with route handler
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
app.get('/me', (req, res) => {
    // `assertAuth` throws 401 if request is not authorized
    const user = assertAuth(req);

    res.send(user);
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
