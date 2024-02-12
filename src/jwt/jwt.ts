import { Response } from 'express';
import { sign } from 'jsonwebtoken';
import uuid from 'uuid';
import { ExtendedNextFunction } from '../types/error';
import { ExtendedRequest } from '../types/extendedRequest';
import { User } from '../types/user';

/** Name of the cookie where to store the jwt payload */
export const JWT_COOKIE_NAME: string = 'token';

/** Jwt payload validity expressed in seconds */
export const JWT_EXPIRES_IN_SECONDS: number = 3600;

/** Generates a jwt token with custom data */
function generateToken(data: User, expiresInSeconds: number): string {
    return sign(data, String(process.env.JWT_SECRET), {
        expiresIn: expiresInSeconds,
        subject: data.userId,
        jwtid: uuid.v4()
    })
}

/** Middleware that puts the `req.user` data into a jwt payload and sets it into a cookie */
export async function setJwtTokenInCookieMiddleware(req: ExtendedRequest, res: Response, next: ExtendedNextFunction): Promise<void> {
    if (req.user) {
        const token: string = generateToken(req.user, JWT_EXPIRES_IN_SECONDS);

        res.cookie(JWT_COOKIE_NAME, token, {
            // Setting expiration in milliseconds
            expires: undefined,
            maxAge: JWT_EXPIRES_IN_SECONDS * 1000,
            httpOnly: true,
            sameSite: "strict",
            secure: true,
        });
    }

    res.status(200).send("OK");

    next();
}