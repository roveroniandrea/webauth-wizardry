import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import express, { Response } from 'express';
import { DummyDB } from './db/dummyDB';
import { setJwtTokenInCookieMiddleware } from './jwt/jwt';
import { ExtendedError, ExtendedNextFunction } from './types/error';
import { ExtendedRequest } from './types/extendedRequest';
import { User } from './types/user';

dotenv.config();

const app = express();
const port = 3000;

app.use(bodyParser.json());

// Catching errors
app.use((err: Error, req: ExtendedRequest, res: Response, next: ExtendedNextFunction): void => {
    if (err instanceof ExtendedError) {
        res.status(err.statusCode).send(err.message);
    }
    else {
        res.status(500).send("Internal Server Error");
    }
});

app.get('/', (req, res) => {
    res.send('Hello World!');
});


// START Email / password
app.post('/signin', async (req: ExtendedRequest, res, next: ExtendedNextFunction) => {
    const { email, password } = req.body;

    if (!email || !password) {
        next(new ExtendedError(400, "Missing required data"));
        return;
    }

    try {
        const user = await DummyDB.getUserByEmailPassword(email, password);
        if (!user) {
            next(new ExtendedError(404, "User not found"));
            return;
        }

        req.user = user;

        next();
    }
    catch {
        next(new ExtendedError(404, "User not found"));
    }
}, setJwtTokenInCookieMiddleware);


app.post('/signup', async (req: ExtendedRequest, res, next: ExtendedNextFunction) => {
    const { email, password } = req.body;

    if (!email || !password) {
        next(new ExtendedError(400, "Missing required data"));
        return;
    }
    try {
        const user = await DummyDB.createUserByEmailPassword(email, password);
        if (!user) {
            next(new ExtendedError(404, "User not found"));
            return;
        }

        req.user = user;

        next();
    }
    catch {
        next(new ExtendedError(404, "User not found"));
    }
}, setJwtTokenInCookieMiddleware);

// END Email / password


app.get('/users', async (_, res) => {
    const users: User[] = await DummyDB.listUsers();

    res.send(users);
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
