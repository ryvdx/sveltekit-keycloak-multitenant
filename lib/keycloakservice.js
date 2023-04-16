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
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.emailValidator = exports.KeyCloakHandle = void 0;
var kit_1 = require("@sveltejs/kit");
var jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
var crypto_random_string_1 = __importDefault(require("crypto-random-string"));
var fs_1 = __importDefault(require("fs"));
var yaml_1 = __importDefault(require("yaml"));
var path_1 = __importDefault(require("path"));
var KEYCLOAK_URL;
var KEYCLOAK_INTERNAL_URL;
var LOGIN_PATH;
var LOGOUT_PATH;
var tenants = {};
var initTenantLookup = function () {
    var pwd = process.env.PWD;
    if (!pwd) {
        throw new Error("process.env.PWD is not set");
    }
    var tenant_path = path_1.default.resolve(pwd, "tenants.yaml");
    if (!fs_1.default.existsSync(tenant_path)) {
        throw new Error("TENANT_YAML file not found at path: ".concat(tenant_path));
    }
    var tenantMetaYaml = fs_1.default.readFileSync(tenant_path).toString();
    try {
        tenants = yaml_1.default.parse(tenantMetaYaml);
    }
    catch (err) {
        throw new Error("TENANT_YAML is not valid YAML. err: err");
    }
    Object.entries(tenants).forEach(function (_a) {
        var key = _a[0], tenant = _a[1];
        tenant.name = key;
    });
};
initTenantLookup();
var emailValidator = function (email) {
    // Credit to https://www.npmjs.com/package/email-validator
    var tester = /^[-!#$%&'*+\/0-9=?A-Z^_a-z`{|}~](\.?[-!#$%&'*+\/0-9=?A-Z^_a-z`{|}~])*@[a-zA-Z0-9](-*\.?[a-zA-Z0-9])*\.[a-zA-Z](-?[a-zA-Z0-9])+$/;
    if (!email)
        return false;
    var emailParts = email.split("@");
    if (emailParts.length !== 2)
        return false;
    var account = emailParts[0];
    var address = emailParts[1];
    if (account.length > 64)
        return false;
    else if (address.length > 255)
        return false;
    var domainParts = address.split(".");
    if (domainParts.some(function (part) {
        return part.length > 63;
    }))
        return false;
    if (!tester.test(email))
        return false;
    return true;
};
exports.emailValidator = emailValidator;
var KeyCloakHelper = {
    getToken: function (tenantMeta, username, password) { return __awaiter(void 0, void 0, void 0, function () {
        var postParms, postParmsFormEncoded, response, _a, _b, err_1;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0:
                    postParms = {
                        grant_type: "authorization_code",
                        username: username,
                        password: password,
                        scope: "openid",
                        client_id: tenantMeta.client_id,
                        client_secret: tenantMeta.client_secret,
                    };
                    postParmsFormEncoded = new URLSearchParams(Object.entries(postParms)).toString();
                    _c.label = 1;
                case 1:
                    _c.trys.push([1, 4, , 5]);
                    return [4 /*yield*/, fetch("".concat(KEYCLOAK_URL, "/realms/").concat(tenantMeta.realm, "/protocol/openid-connect/auth"), {
                            method: "POST",
                            headers: { "Content-Type": "application/x-www-form-urlencoded" },
                            body: postParmsFormEncoded,
                        })];
                case 2:
                    response = _c.sent();
                    _b = (_a = JSON).parse;
                    return [4 /*yield*/, response.text()];
                case 3: return [2 /*return*/, _b.apply(_a, [_c.sent()])];
                case 4:
                    err_1 = _c.sent();
                    throw err_1;
                case 5: return [2 /*return*/];
            }
        });
    }); },
    getLoginForwardUrl: function (tenantMeta, csrfCode, urlOrigin, email) {
        var redirect_uri = "".concat(urlOrigin).concat(LOGIN_PATH, "/response");
        var queryParameters = {
            response_type: "code",
            client_id: tenantMeta.client_id,
            redirect_uri: redirect_uri,
            response_mode: "jwt",
            scope: "openid roles email profile",
            grant_type: "authorization_code",
            state: csrfCode,
            login_hint: !email ? "" : email,
        };
        var queryString = Object.entries(queryParameters)
            .map(function (_a) {
            var key = _a[0], value = _a[1];
            return "".concat(key, "=").concat(encodeURIComponent(value));
        })
            .join("&");
        // Redirect to Authentication Server
        return "".concat(KEYCLOAK_URL, "/realms/").concat(tenantMeta.realm, "/protocol/openid-connect/auth?").concat(queryString);
    },
    login: function (tenantMeta, username, password) { return __awaiter(void 0, void 0, void 0, function () {
        var postParms, postParmsFormEncoded, response, _a, _b, err_2;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0:
                    postParms = {
                        grant_type: "password",
                        username: username,
                        password: password,
                        scope: "openid",
                        client_id: tenantMeta.client_id,
                        client_secret: tenantMeta.client_secret,
                    };
                    postParmsFormEncoded = new URLSearchParams(Object.entries(postParms)).toString();
                    _c.label = 1;
                case 1:
                    _c.trys.push([1, 4, , 5]);
                    return [4 /*yield*/, fetch("".concat(KEYCLOAK_URL, "/realms/").concat(tenantMeta.realm, "/protocol/openid-connect/token"), {
                            method: "POST",
                            headers: { "Content-Type": "application/x-www-form-urlencoded" },
                            body: postParmsFormEncoded,
                        })];
                case 2:
                    response = _c.sent();
                    _b = (_a = JSON).parse;
                    return [4 /*yield*/, response.text()];
                case 3: return [2 /*return*/, _b.apply(_a, [_c.sent()])];
                case 4:
                    err_2 = _c.sent();
                    throw err_2;
                case 5: return [2 /*return*/];
            }
        });
    }); },
    exchangeOneTimeCodeForAccessToken: function (tenantMeta, oneTimeCode, event) { return __awaiter(void 0, void 0, void 0, function () {
        var postParmsFormEncoded, response, responseText, openIdResp;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    postParmsFormEncoded = KeyCloakHelper.convertParmsForBody({
                        client_id: tenantMeta.client_id,
                        client_secret: tenantMeta.client_secret,
                        redirect_uri: "".concat(event.url.origin).concat(LOGIN_PATH, "/response"),
                        response_mode: "jwt",
                        scope: "openid",
                        grant_type: "authorization_code",
                        code: oneTimeCode,
                    });
                    return [4 /*yield*/, fetch("".concat(KEYCLOAK_INTERNAL_URL, "/realms/").concat(tenantMeta.realm, "/protocol/openid-connect/token"), {
                            method: "POST",
                            headers: { "Content-Type": "application/x-www-form-urlencoded" },
                            body: postParmsFormEncoded,
                        })];
                case 1:
                    response = _a.sent();
                    return [4 /*yield*/, response.text()];
                case 2:
                    responseText = _a.sent();
                    openIdResp = JSON.parse(responseText);
                    return [2 /*return*/, openIdResp];
            }
        });
    }); },
    refresh: function (tenantMeta, refreshCookie) { return __awaiter(void 0, void 0, void 0, function () {
        var postParms, postParmsFormEncoded, response, _a, _b, err_3;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0:
                    if (!refreshCookie) {
                        throw new Error("No Refresh Token Found");
                    }
                    postParms = {
                        client_id: tenantMeta.client_id,
                        client_secret: tenantMeta.client_secret,
                        grant_type: "refresh_token",
                        token_type_hint: "access_token",
                        refresh_token: refreshCookie,
                    };
                    postParmsFormEncoded = new URLSearchParams(Object.entries(postParms)).toString();
                    _c.label = 1;
                case 1:
                    _c.trys.push([1, 4, , 5]);
                    return [4 /*yield*/, fetch("".concat(KEYCLOAK_INTERNAL_URL, "/realms/").concat(tenantMeta.realm, "/protocol/openid-connect/token"), {
                            method: "POST",
                            headers: { "Content-Type": "application/x-www-form-urlencoded" },
                            body: postParmsFormEncoded,
                        })];
                case 2:
                    response = _c.sent();
                    _b = (_a = JSON).parse;
                    return [4 /*yield*/, response.text()];
                case 3: return [2 /*return*/, _b.apply(_a, [_c.sent()])];
                case 4:
                    err_3 = _c.sent();
                    console.error("Token Refresh Failed: ".concat(err_3, "}"));
                    throw err_3;
                case 5: return [2 /*return*/];
            }
        });
    }); },
    logout: function (tenantMeta, refreshCookie) { return __awaiter(void 0, void 0, void 0, function () {
        var decoded, postParms, postParmsFormEncoded, response, err_4;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    decoded = jsonwebtoken_1.default.decode(refreshCookie);
                    postParms = {
                        client_id: tenantMeta.client_id,
                        client_secret: tenantMeta.client_secret,
                        token_type_hint: "access_token",
                        token: decoded.sid,
                        grant_type: "refresh_token",
                        refresh_token: refreshCookie,
                    };
                    postParmsFormEncoded = new URLSearchParams(Object.entries(postParms)).toString();
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, fetch("".concat(KEYCLOAK_INTERNAL_URL, "/realms/").concat(tenantMeta.realm, "/protocol/openid-connect/logout"), {
                            method: "POST",
                            headers: { "Content-Type": "application/x-www-form-urlencoded" },
                            body: postParmsFormEncoded,
                        })];
                case 2:
                    response = _a.sent();
                    return [2 /*return*/, response.status === 204];
                case 3:
                    err_4 = _a.sent();
                    console.error("logout response error");
                    throw err_4;
                case 4: return [2 /*return*/];
            }
        });
    }); },
    getByTenantName: function (tenantName) {
        if (!tenantName) {
            throw new Error("Tenant Name undefined");
        }
        if (!tenants[tenantName.toLowerCase()]) {
            throw new Error("Tenant ".concat(tenantName, " not found"));
        }
        return tenants[tenantName.toLowerCase()];
    },
    getTenantByEmail: function (email) {
        initTenantLookup(); // TODO: can do this conditionally later, for now forces reading file at login.
        var userEmailDomain = email.split("@")[1].toLowerCase();
        var thisTenant = Object.values(tenants).filter(function (value) {
            return value.email_domain === userEmailDomain;
        });
        if (thisTenant.length === 0) {
            throw new Error("No tenant matching ".concat(email, " domain"));
        }
        return thisTenant[0];
    },
    convertParmsForBody: function (parmObj) {
        return new URLSearchParams(Object.entries(parmObj)).toString();
    },
};
var expireAuthCookies = function (event) {
    [
        "AuthorizationToken",
        "RefreshToken",
        "IdToken",
        "LastPath",
        "csrfCode",
        "tenant",
    ].forEach(function (cookieName) {
        event.cookies.set(cookieName, "", {
            httpOnly: true,
            path: "/",
            secure: true,
            sameSite: "strict",
            maxAge: 0,
        });
    });
};
var kcHandle = function (_a) {
    var event = _a.event, resolve = _a.resolve;
    return __awaiter(void 0, void 0, void 0, function () {
        var refreshTokenCookie, pathIs, csrfCode, clientCode, data, email, validEmail, csrfCode, loginUrl, tenantMeta_1, loginResponse, decoded_1, csrfCode, tenantName_1, tenantMeta_2, openIdResp, accessToken, err_5, LastPath, decoded, tenantName, tenantMeta, refreshMeta, accessMeta, response, err_6, err_7, clientCode;
        var _b, _c;
        return __generator(this, function (_d) {
            switch (_d.label) {
                case 0:
                    refreshTokenCookie = event.cookies.get("RefreshToken");
                    pathIs = [LOGIN_PATH, "".concat(LOGIN_PATH, "/response"), LOGOUT_PATH];
                    if (!refreshTokenCookie && pathIs.indexOf(event.url.pathname) == -1) {
                        // console.log('1: Storing last path in cookie');
                        event.cookies.set("LastPath", event.url.pathname, {
                            httpOnly: true,
                            path: "/",
                            secure: true,
                            sameSite: "strict",
                            maxAge: 60 * 10,
                        });
                        // If we don't have a refresh token, redirect to the login page if they aren't currently there.
                        throw (0, kit_1.redirect)(302, LOGIN_PATH);
                    }
                    if (!(!refreshTokenCookie &&
                        event.url.pathname === LOGIN_PATH &&
                        event.request.method === "GET")) return [3 /*break*/, 2];
                    csrfCode = event.cookies.get("csrfCode");
                    if (!csrfCode) {
                        clientCode = (0, crypto_random_string_1.default)({ length: 16, type: "url-safe" });
                        event.cookies.set("csrfCode", clientCode, {
                            httpOnly: true,
                            path: "/",
                            secure: true,
                            sameSite: "strict",
                            maxAge: 60 * 5, // 5 minute duration for the CSRF cookie
                        });
                    }
                    return [4 /*yield*/, resolve(event)];
                case 1: return [2 /*return*/, _d.sent()];
                case 2:
                    if (!(event.url.pathname === LOGIN_PATH &&
                        event.request.method === "POST" &&
                        event.url.search === "?/login")) return [3 /*break*/, 4];
                    return [4 /*yield*/, event.request.formData()];
                case 3:
                    data = _d.sent();
                    email = (_b = data.get("email")) === null || _b === void 0 ? void 0 : _b.toString();
                    validEmail = !!email ? emailValidator(email) : false;
                    if (!validEmail || !email) {
                        console.error("Invalid email address: ".concat(email));
                        throw (0, kit_1.redirect)(303, "".concat(LOGIN_PATH, "?err=invalidemail"));
                    }
                    csrfCode = event.cookies.get("csrfCode");
                    if (!csrfCode) {
                        throw (0, kit_1.redirect)(303, LOGIN_PATH);
                    }
                    loginUrl = "";
                    try {
                        tenantMeta_1 = KeyCloakHelper.getTenantByEmail(email);
                        loginUrl = KeyCloakHelper.getLoginForwardUrl(tenantMeta_1, csrfCode, event.url.origin, email);
                    }
                    catch (err) {
                        console.error("Keycloakservice login error. Client: ".concat(event.getClientAddress(), ", Error: ").concat(err));
                        throw (0, kit_1.redirect)(303, LOGIN_PATH);
                    }
                    throw (0, kit_1.redirect)(303, loginUrl);
                case 4:
                    if (!(event.url.pathname === "".concat(LOGIN_PATH, "/response"))) return [3 /*break*/, 9];
                    loginResponse = event.url.searchParams.get("response");
                    if (!loginResponse) {
                        expireAuthCookies(event);
                        throw (0, kit_1.redirect)(302, LOGIN_PATH);
                    }
                    decoded_1 = jsonwebtoken_1.default.decode(loginResponse);
                    csrfCode = event.cookies.get("csrfCode");
                    if (decoded_1.state !== csrfCode) {
                        console.error("CSRF Code Mismatch! Do not trust this response!");
                        expireAuthCookies(event);
                        event.locals.user = null;
                        throw (0, kit_1.redirect)(302, LOGIN_PATH);
                    }
                    if (!decoded_1.iss) {
                        console.error('No "iss" in response, reqiured to get tenant/realm.');
                        throw (0, kit_1.redirect)(302, LOGIN_PATH);
                    }
                    _d.label = 5;
                case 5:
                    _d.trys.push([5, 7, , 8]);
                    tenantName_1 = decoded_1.iss.split("/realms/")[1];
                    tenantMeta_2 = KeyCloakHelper.getByTenantName(tenantName_1);
                    return [4 /*yield*/, KeyCloakHelper.exchangeOneTimeCodeForAccessToken(tenantMeta_2, decoded_1.code, event)];
                case 6:
                    openIdResp = _d.sent();
                    event.cookies.set("RefreshToken", openIdResp.refresh_token, {
                        httpOnly: true,
                        path: "/",
                        secure: true,
                        sameSite: "strict",
                        maxAge: openIdResp.refresh_expires_in,
                    });
                    event.cookies.set("IdToken", openIdResp.id_token, {
                        httpOnly: true,
                        path: "/",
                        secure: true,
                        sameSite: "strict",
                        maxAge: 60 * 60 * 10, // 10 hours (no explicit value from keycloak, Auth0 says 10 hours is their standard, copying that)
                    });
                    accessToken = jsonwebtoken_1.default.decode(openIdResp.access_token);
                    event.locals.user = {
                        loggedIn: true,
                        username: accessToken.name,
                        email: accessToken.email,
                        tenant: tenantMeta_2.name,
                        roles: accessToken.realm_access.roles,
                    };
                    return [3 /*break*/, 8];
                case 7:
                    err_5 = _d.sent();
                    console.error("Unable to Obtain Access Code from One-Time-use Code");
                    console.error(err_5);
                    expireAuthCookies(event);
                    event.locals.user = null;
                    throw (0, kit_1.redirect)(302, LOGIN_PATH);
                case 8:
                    LastPath = event.cookies.get("LastPath");
                    throw (0, kit_1.redirect)(302, !LastPath ? "/" : LastPath);
                case 9:
                    if (!(!refreshTokenCookie && event.url.pathname === LOGOUT_PATH)) return [3 /*break*/, 11];
                    return [4 /*yield*/, resolve(event)];
                case 10: 
                // console.log('5: !refreshTokenCookie && event.url.pathname === LOGOUT_PATH');
                return [2 /*return*/, _d.sent()];
                case 11:
                    decoded = jsonwebtoken_1.default.decode(refreshTokenCookie !== null && refreshTokenCookie !== void 0 ? refreshTokenCookie : "");
                    tenantName = ((_c = decoded.iss) !== null && _c !== void 0 ? _c : "").toLowerCase().split("/realms/")[1];
                    tenantMeta = KeyCloakHelper.getByTenantName(tenantName);
                    if (!tenantMeta) {
                        expireAuthCookies(event);
                        event.locals.user = null;
                        throw (0, kit_1.redirect)(302, LOGIN_PATH);
                    }
                    if (!(refreshTokenCookie && pathIs.indexOf(event.url.pathname) === -1)) return [3 /*break*/, 16];
                    _d.label = 12;
                case 12:
                    _d.trys.push([12, 15, , 16]);
                    return [4 /*yield*/, KeyCloakHelper.refresh(tenantMeta, refreshTokenCookie)];
                case 13:
                    refreshMeta = _d.sent();
                    event.cookies.set("RefreshToken", refreshMeta.refresh_token, {
                        httpOnly: true,
                        path: "/",
                        secure: true,
                        sameSite: "strict",
                        maxAge: refreshMeta.refresh_expires_in,
                    });
                    if (refreshMeta.error) {
                        // Note: this will set the short term CSRF cookie on landing at /auth/login when hooks.server.ts is invoked again
                        console.error("KeyCloakService: Token Refresh Failed. Clear cookies return to login page. Message: ".concat(refreshMeta.error_description));
                        event.cookies.set("RefreshToken", "", {
                            httpOnly: true,
                            path: "/",
                            secure: true,
                            sameSite: "strict",
                            maxAge: 0,
                        });
                        event.locals.user = null;
                        throw (0, kit_1.redirect)(302, LOGIN_PATH);
                    }
                    accessMeta = jsonwebtoken_1.default.decode(refreshMeta.access_token);
                    event.locals.user = {
                        loggedIn: true,
                        username: accessMeta.name,
                        email: accessMeta.email,
                        tenant: tenantMeta.name,
                        roles: accessMeta.realm_access.roles,
                    };
                    return [4 /*yield*/, resolve(event)];
                case 14:
                    response = _d.sent();
                    return [2 /*return*/, response];
                case 15:
                    err_6 = _d.sent();
                    // Note: this will set the short term CSRF cookie on landing at /login when hooks.server.ts is invoked again
                    expireAuthCookies(event);
                    event.locals.user = null;
                    throw (0, kit_1.redirect)(302, LOGIN_PATH);
                case 16:
                    if (!(refreshTokenCookie && event.url.pathname === LOGOUT_PATH)) return [3 /*break*/, 22];
                    _d.label = 17;
                case 17:
                    _d.trys.push([17, 19, , 20]);
                    return [4 /*yield*/, KeyCloakHelper.logout(tenantMeta, refreshTokenCookie)];
                case 18:
                    _d.sent();
                    return [3 /*break*/, 20];
                case 19:
                    err_7 = _d.sent();
                    console.error("Logout Failed! ".concat(err_7));
                    return [3 /*break*/, 20];
                case 20:
                    expireAuthCookies(event);
                    event.locals.user = null;
                    clientCode = (0, crypto_random_string_1.default)({ length: 16, type: "url-safe" });
                    event.cookies.set("csrfCode", clientCode, {
                        httpOnly: true,
                        path: "/",
                        secure: true,
                        sameSite: "strict",
                        maxAge: 60 * 5, // 5 minute duration for the CSRF cookie
                    });
                    return [4 /*yield*/, resolve(event)];
                case 21:
                    _d.sent();
                    throw (0, kit_1.redirect)(302, LOGOUT_PATH);
                case 22: return [4 /*yield*/, resolve(event)];
                case 23: 
                // console.log('9: Fell through logic, resolving');
                return [2 /*return*/, _d.sent()];
            }
        });
    });
};
var KeyCloakHandle = function (config) {
    KEYCLOAK_URL = config.keycloakUrl;
    KEYCLOAK_INTERNAL_URL = config.keycloakInternalUrl;
    LOGIN_PATH = config.loginPath;
    LOGOUT_PATH = config.logoutPath;
    return kcHandle;
};
exports.KeyCloakHandle = KeyCloakHandle;
//# sourceMappingURL=keycloakservice.js.map