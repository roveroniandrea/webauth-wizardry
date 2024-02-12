import * as dotenv from 'dotenv';
import express from 'express';
import { createUserByEmailPassword, getUserByEmailPassword, listUsers } from './db/db';
import { ExtendedRequest } from './types/extendedRequest';
import { User } from './types/user';
import bodyParser from 'body-parser';
import { setJwtTokenInCookieMiddleware } from './jwt/jwt';

dotenv.config();

const app = express();
const port = 3000;

app.use(bodyParser.json())

app.get('/', (req, res) => {
    res.send('Hello World!');
});

// TODO: better error handling: currently results in an html response

// Email / password
app.post('/signin', async (req: ExtendedRequest, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
        next("Missing required data");
        return;
    }

    try {
        const user = await getUserByEmailPassword(email, password);
        if (!user) {
            next("User not found");
            return;
        }

        req.user = user;

        next();
    }
    catch {
        next("User not found");
    }
}, setJwtTokenInCookieMiddleware);

app.post('/signup', async (req: ExtendedRequest, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
        next("Missing required data");
        return;
    }
    try {
        const user = await createUserByEmailPassword(email, password);
        if (!user) {
            next("User not found");
            return;
        }

        req.user = user;

        next();
    }
    catch {
        next("User not found");
    }
}, setJwtTokenInCookieMiddleware);


app.get('/users', async (_, res) => {
    const users: User[] = await listUsers();

    res.send(users);
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
