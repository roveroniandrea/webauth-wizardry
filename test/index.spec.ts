import dotenv from 'dotenv';
import express from 'express';
import { RedisClientType, createClient } from 'redis';
import { ExtendedError, ExtendedNextFunction, ExtendedRequest, ExtendedResponse, GOOGLE_ISSUER_METADATA, User, WebauthWizardryForExpress, assertAuth, assertAuthMiddleware } from '../src';
import { DummyDB } from './utils/dummyDB';

// Loading dotenv
dotenv.config();

const app = express();
const port = 3000;

const redisClient: RedisClientType = createClient();
// Redis will automatically try to reconnect
redisClient.on('error', err => console.log('Redis Client Error', err))
    .on('ready', () => console.log('Redis is ready, check http://localhost:8001 for Redis Insight'));

const dbClient = new DummyDB();

const webauthWizardry = new WebauthWizardryForExpress({
    router: app,
    SECRETS: {
        JWT_SECRET: process.env.JWT_SECRET || '',
        COOKIE_PARSER_SECRET: process.env.COOKIE_PARSER_SECRET || ''
    },
    redisClient: redisClient,
    dbClient: dbClient,
    // Config related to server
    serverConfig: {
        serverBaseUrl: "http://localhost:80/api"
    }
})
    .withEmailPasswordAuth({
        onEmailVerificationCode: (email: string, code: string) => {
            console.log(`
            \n\nEMAIL VERIFICATION for email ${email} with code ${code}:
            http://localhost:80/verifyEmail/${code}
            \n\n`);
        }
    })
    // TODO: Maybe wrap as a function that accepts secrets, provider name and a function to generate the discoverable url
    .withOpenIdProviders([{
        providerName: 'google',
        issuerMetadata: GOOGLE_ISSUER_METADATA,
        clientId: process.env.GOOGLE_CLIENT_ID || '',
        clientSecret: process.env.GOOGLE_CLIENT_SECRET || ''
    }], {});

// This route does not require authentication
app.get('/', (req: ExtendedRequest, res: ExtendedResponse<string>) => {
    res.send({
        error: null,
        data: 'Hello World!'
    });
});


app.get('/users', async (_, res) => {
    const users: User[] = await dbClient.listUsers();

    res.send(users);
});


// Retrieves info about the current logged user
// This endpoint requires authentication
// See also /me/middleware route
app.get('/me', (req: ExtendedRequest, res: ExtendedResponse<User>) => {
    // `assertAuth` throws 401 if request is not authorized
    const user = assertAuth(req);

    res.send({
        error: null,
        data: user
    });
});


// Retrieves info about the current logged user but using a middleware
// This endpoint requires authentication
// See also /me route
app.get('/me/middleware', assertAuthMiddleware(), (req: ExtendedRequest, res: ExtendedResponse<User>) => {
    res.send({
        error: null,
        data: req.user as User
    });
});


// Catching errors
// This needs to be defined as last middleware to intercept everything
app.use((err: Error, req: ExtendedRequest, res: ExtendedResponse, next: ExtendedNextFunction): void => {
    if (err instanceof ExtendedError) {
        res.status(err.statusCode).send({
            error: err.message,
            data: null
        });
    }
    else {
        console.error(`Found error:`, err);

        res.status(500).send({
            error: "Internal Server Error",
            data: null
        });
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

