import { User } from '../types/user';
import { sign } from 'jsonwebtoken'
import { v4 as uuidV4 } from 'uuid';
import { ExtendedRequest } from '../types/extendedRequest';
import { NextFunction, Response } from 'express';

export const JWT_COOKIE_NAME: string = 'token';

function generateToken(data: User, expiresInSeconds: number): string {
    return sign(data, String(process.env.JWT_SECRET), {
        expiresIn: expiresInSeconds,
        subject: data.userId,
        jwtid: uuidV4()
    })
}

export async function setJwtTokenInCookieMiddleware(req: ExtendedRequest, res: Response, next: NextFunction): Promise<void> {
    if (req.user) {
        // 1h token validity
        const expiresInSeconds = 3600;

        const token: string = generateToken(req.user, expiresInSeconds);


        res.cookie(JWT_COOKIE_NAME, token, {
            // Setting expiration in milliseconds
            expires: undefined,
            maxAge: expiresInSeconds * 1000,
            httpOnly: true,
            sameSite: "strict",
            secure: true,
        });
    }

    res.status(200);

    res.send("OK")

    next();
}