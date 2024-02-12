"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.setJwtTokenInCookieMiddleware = exports.JWT_COOKIE_NAME = void 0;
const jsonwebtoken_1 = require("jsonwebtoken");
const uuid_1 = require("uuid");
exports.JWT_COOKIE_NAME = 'token';
function generateToken(data, expiresInSeconds) {
    return (0, jsonwebtoken_1.sign)(data, String(process.env.JWT_SECRET), {
        expiresIn: expiresInSeconds,
        subject: data.userId,
        jwtid: (0, uuid_1.v4)()
    });
}
function setJwtTokenInCookieMiddleware(req, res, next) {
    return __awaiter(this, void 0, void 0, function* () {
        if (req.user) {
            // 1h token validity
            const expiresInSeconds = 3600;
            const token = generateToken(req.user, expiresInSeconds);
            res.cookie(exports.JWT_COOKIE_NAME, token, {
                // Setting expiration in milliseconds
                expires: undefined,
                maxAge: expiresInSeconds * 1000,
                httpOnly: true,
                sameSite: "strict",
                secure: true,
            });
        }
        res.status(200);
        res.send("OK");
        next();
    });
}
exports.setJwtTokenInCookieMiddleware = setJwtTokenInCookieMiddleware;
//# sourceMappingURL=jwt.js.map