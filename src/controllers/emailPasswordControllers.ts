import { NextFunction } from 'express';
import { getAndDeleteEmailVerificationCode, setEmailVerificationCode } from '../redis/redis';
import { BadRequestError, ExtendedError, ExtendedNextFunction, UserNotFoundError } from '../types/error';
import { ExpressMiddleware, ExtendedRequest, ExtendedResponse } from '../types/express';
import { User } from '../types/user';
import { WebauthWizardryConfig } from '../types/webauth-wizardry';
import { hashPassword, randomUrlSafeString } from '../utils';


/** Default email verification code expiration */
const DEFAULT_EMAIL_VERIFICATION_LINK_EXPIRES_IN_SECONDS: number = 3600 * 24; // 1 day


export type EmailPwConfig = {
    /** Custom verification code validity in seconds */
    verificationLinkExpiresInSeconds?: number;
    /**
     * Invoked when a certain email address needs to be verified
     * Must generate a link pointing to an address on FE, that includes the verification code
     * 
     * FE must then perform a POST call to email verification endpoint
     */
    onEmailVerificationCode: (email: string, code: string) => void | Promise<void>;
}


/**
 * Handles sign in via email/password.
 * 
 * Sets `res.user` for the next middleware, or calls the next middleware with an error
 */
export function signInController(config: WebauthWizardryConfig): ExpressMiddleware {
    return async (req: ExtendedRequest, res: ExtendedResponse, next: ExtendedNextFunction) => {
        const { email, password } = req.body;

        if (!email || !password) {
            next(new BadRequestError());
            return;
        }

        try {
            const user = await config.dbClient.getUserByEmailPassword(email, password);
            if (!user) {
                // Return a generic error
                next(new UserNotFoundError());
                return;
            }

            req.user = user;

            next();
        }
        catch {
            // Return a generic error
            next(new UserNotFoundError());
        }
    };
}


/**
 * Used to create an account with email/password
 * 
 * If succeeded, calls the next middleware without any additional infos
 */
export function signUpController(config: WebauthWizardryConfig, emailPwConfig: EmailPwConfig): ExpressMiddleware<string> {
    return async (req: ExtendedRequest, res: ExtendedResponse<string>, next: ExtendedNextFunction) => {
        const { email, password } = req.body;

        if (!email || !password) {
            next(new BadRequestError());
            return;
        }

        // First, check if this email address already exists
        const userWithSameEmail: User | null = await config.dbClient.getUserByEmail(email);

        if (userWithSameEmail) {
            // In this case the email already exists. It might be for two reasons: 
            // 1 - User has already registered with some other methods (openID providers for example).
            //      This implies that no password is set for this user
            //      Also, since openID providers MUST provide verified emails, this assumes that that user owns that email
            // 2 - Email is already taken. This implies that a password already exists

            const passwordAlreadySet: boolean = await config.dbClient.isPasswordSetForUserId(userWithSameEmail.userId);

            if (passwordAlreadySet) {
                // This is case #2

                // Return a generic error stating that the email address is not available for some reason
                // This has less information disclosure than an explicit "Email already taken"
                next(new ExtendedError(400, "Email address not available"));
                return;
            }

            // Otherwise, case #1

            // The provided email needs to be verified before allowing to use this password,
            // This solves "what if the user already exists because it has signed in with an OpenID provider?"
            // Letting an email/password to merge an already existing user (signed is with another method) would allow anyone to set a custom pw
            // and authenticate as any already registered email
            //
            // The best thing is to only accept verified emails, like for openID signup.
            // So this request will not create a user on db, but rather geenerate a verification code,
            // saving its temporary data (email/pw) on redis, pointed by the code
            //
            // The code can be consumed with a POST request.
            // Then the right redis entry is recovered and saved on db
            // In this way, unverified emails are never saved on db

            const verificationCode: string = await randomUrlSafeString(20);

            // Set both the verification code and email/pw data on redis
            await setEmailVerificationCode(config.redisClient, verificationCode, emailPwConfig.verificationLinkExpiresInSeconds || DEFAULT_EMAIL_VERIFICATION_LINK_EXPIRES_IN_SECONDS, {
                mustMergeUser: true,
                userIdToMerge: userWithSameEmail.userId,
                hashedPw: await hashPassword(password)
            });

            // Invoke the callback. This callback should generate an email to that user
            await emailPwConfig.onEmailVerificationCode(email, verificationCode);

            // Then, proceed
            next();
            return;
        }
        else {
            // Otherwise, no other users exist with the same password
            // The step is similar to the # 1 case on the other condition
            // The only difference is that the user must not be merged, but instead created as new

            const verificationCode: string = await randomUrlSafeString(20);

            // Set both the verification code and email/pw data on redis
            await setEmailVerificationCode(config.redisClient, verificationCode, emailPwConfig.verificationLinkExpiresInSeconds || DEFAULT_EMAIL_VERIFICATION_LINK_EXPIRES_IN_SECONDS, {
                mustMergeUser: false,
                email: email,
                hashedPw: await hashPassword(password)
            });

            // Invoke the callback. This callback should generate an email to that user
            await emailPwConfig.onEmailVerificationCode(email, verificationCode);

            // Then, proceed
            next();
            return;
        }
    }
}


/** 
 * Used to verify an email address providing a verification code
 * 
 * If succeeded, calls the next middleware (without any user set)
 */
export function emailVerificationController(config: WebauthWizardryConfig): ExpressMiddleware {
    return async (req: ExtendedRequest, res: ExtendedResponse, next: NextFunction) => {

        const verificationCode: string | null = req.body.verificationCode;
        // Retrieve and immediately invalidate the verification code
        const verificationData = verificationCode ? await getAndDeleteEmailVerificationCode(config.redisClient, verificationCode) : null;

        if (!verificationData) {
            // If the verification code does not exist, end here
            next(new ExtendedError(401, "Invalid verification code"));
            return;
        }

        // Else, depends on what action needs to be performed
        try {
            if (verificationData.mustMergeUser) {
                // Here, user must be merged.
                // It's the case when `userWithSameEmail` exists
                await config.dbClient.createPasswordForUser(verificationData.userIdToMerge, verificationData.hashedPw);
            }
            else {
                // Otherwise a new user must be created
                const newUser: User = await config.dbClient.createUserByEmail(verificationData.email);

                await config.dbClient.createPasswordForUser(newUser.userId, verificationData.hashedPw);
            }
        }
        catch (ex) {
            // Process might fail if during the meantime (from code generation and email verification)
            // something has changed with the registered email (maybe user deleted when previously existed, or vice versa)
            console.error(ex);
            next(new ExtendedError(500, "Cannot verify email"));
            return;
        }


        // Operation succeeded, but do not authenticate anything, require a manual authentication
        // to prevent confusing behavior to the user
        next();
    }
}