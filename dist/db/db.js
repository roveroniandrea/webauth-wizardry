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
exports.listUsers = exports.getUserByUserId = exports.getUserByEmailPassword = exports.createUserByEmailPassword = void 0;
const uuid_1 = require("uuid");
const bcrypt_1 = require("bcrypt");
const USERS_TABLE = [];
const PASSWORD_BY_USER = new Map();
function createUserByEmailPassword(email, password) {
    return __awaiter(this, void 0, void 0, function* () {
        if (USERS_TABLE.some(u => u.email === email)) {
            throw new Error("Email already used");
        }
        const user = {
            userId: (0, uuid_1.v4)(),
            email: email
        };
        USERS_TABLE.push(user);
        const hashedPw = yield (0, bcrypt_1.hash)(password, 10);
        PASSWORD_BY_USER.set(user.userId, hashedPw);
        return user;
    });
}
exports.createUserByEmailPassword = createUserByEmailPassword;
function getUserByEmailPassword(email, password) {
    return __awaiter(this, void 0, void 0, function* () {
        const user = USERS_TABLE.find(u => u.email === email) || null;
        if (user) {
            const hashedPw = PASSWORD_BY_USER.get(user.userId) || null;
            if (hashedPw) {
                const isPwOk = yield (0, bcrypt_1.compare)(password, hashedPw);
                if (isPwOk) {
                    return user;
                }
            }
        }
        return null;
    });
}
exports.getUserByEmailPassword = getUserByEmailPassword;
function getUserByUserId(userId) {
    return __awaiter(this, void 0, void 0, function* () {
        const user = USERS_TABLE.find(u => u.userId === userId) || null;
        if (!user) {
            throw new Error("User not found");
        }
        return user;
    });
}
exports.getUserByUserId = getUserByUserId;
function listUsers() {
    return __awaiter(this, void 0, void 0, function* () {
        return Promise.resolve(USERS_TABLE);
    });
}
exports.listUsers = listUsers;
//# sourceMappingURL=db.js.map