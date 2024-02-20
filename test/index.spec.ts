import dotenv from 'dotenv';
import express, { Response } from 'express';
import { RedisClientType, createClient } from 'redis';
import { ExtendedError, ExtendedNextFunction, ExtendedRequest, User, WebauthWizardryForExpress, assertAuth, assertAuthMiddleware } from '../src';
import { DummyDB } from '../src/db/dummyDB';
import { Issuer } from 'openid-client';

// Loading dotenv
dotenv.config();

const app = express();
const port = 3000;

const redisClient: RedisClientType = createClient();
// Redis will automatically try to reconnect
redisClient.on('error', err => console.log('Redis Client Error', err))
    .on('ready', () => console.log('Redis is ready'));

const dbClient = new DummyDB();

const webauthWizardry = new WebauthWizardryForExpress({
    router: app,
    SECRETS: {
        JWT_SECRET: process.env.JWT_SECRET || '',
        COOKIE_PARSER_SECRET: process.env.COOKIE_PARSER_SECRET || ''
    },
    redisClient: redisClient,
    dbClient: dbClient
})
    .withEmailPasswordAuth()
    .withOpenIdProviders([{
        providerName: "google",
        issuerMetadata: {
            "issuer": "https://accounts.google.com",
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "device_authorization_endpoint": "https://oauth2.googleapis.com/device/code",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
            "revocation_endpoint": "https://oauth2.googleapis.com/revoke",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
            "response_types_supported": [
                "code",
                "token",
                "id_token",
                "code token",
                "code id_token",
                "token id_token",
                "code token id_token",
                "none"
            ],
            "subject_types_supported": [
                "public"
            ],
            "id_token_signing_alg_values_supported": [
                "RS256"
            ],
            "scopes_supported": [
                "openid",
                "email",
                "profile"
            ],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic"
            ],
            "claims_supported": [
                "aud",
                "email",
                "email_verified",
                "exp",
                "family_name",
                "given_name",
                "iat",
                "iss",
                "name",
                "picture",
                "sub"
            ],
            "code_challenge_methods_supported": [
                "plain",
                "S256"
            ],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
                "urn:ietf:params:oauth:grant-type:jwt-bearer"
            ]
        },
        clientId: process.env.GOOGLE_CLIENT_ID || '',
        clientSecret: process.env.GOOGLE_CLIENT_SECRET || ''
    }], {
        serverPort: port
    });

// This route does not require authentication
app.get('/', (req, res) => {
    res.send('Hello World!');
});


app.get('/users', async (_, res) => {
    const users: User[] = await dbClient.listUsers();

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


// Init redis client
redisClient.connect()
    .then(() => {
        // Start listening
        app.listen(port, () => {
            console.log(`Server listening on port ${port}`);
        });
    })

