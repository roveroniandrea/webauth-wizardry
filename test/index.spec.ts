import dotenv from 'dotenv';
import express, { Response } from 'express';
import { RedisClientType, createClient } from 'redis';
import { ExtendedError, ExtendedNextFunction, ExtendedRequest, GOOGLE_ISSUER_METADATA, User, WebauthWizardryForExpress, assertAuth, assertAuthMiddleware } from '../src';
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
    // TODO: Maybe wrap as a function that accepts secrets, provider name and a function to generate the discoverable url
    .withOpenIdProviders([{
        providerName: 'google',
        issuerMetadata: GOOGLE_ISSUER_METADATA,
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

