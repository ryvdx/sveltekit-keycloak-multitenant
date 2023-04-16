import { redirect, type Handle, type RequestEvent } from "@sveltejs/kit";
import jwt from "jsonwebtoken";
import cryptoRandomString from "crypto-random-string";
import fs from "fs";
import YAML from "yaml";
import path from "path";

let KEYCLOAK_URL: string;
let KEYCLOAK_INTERNAL_URL: string;
let LOGIN_PATH: string;
let LOGOUT_PATH: string;

interface UserInfo {
  username: string;
  email: string;
  loggedIn: boolean;
  roles: string[];
  tenant: string;
}

interface TenantMeta {
  name: string;
  client_id: string;
  client_secret: string;
  realm: string;
  email_domain: string;
}
interface AllTenants {
  [details: string]: TenantMeta;
}

let tenants: AllTenants = {};
const initTenantLookup = () => {
  const pwd = process.env.PWD;
  if (!pwd) {
    throw new Error("process.env.PWD is not set");
  }
  const tenant_path = path.resolve(pwd, "tenants.yaml");

  if (!fs.existsSync(tenant_path)) {
    throw new Error(`TENANT_YAML file not found at path: ${tenant_path}`);
  }
  const tenantMetaYaml = fs.readFileSync(tenant_path).toString();

  try {
    tenants = YAML.parse(tenantMetaYaml) as AllTenants;
  } catch (err) {
    throw new Error(`TENANT_YAML is not valid YAML. err: err`);
  }

  Object.entries(tenants).forEach(([key, tenant]) => {
    tenant.name = key;
  });
};

initTenantLookup();

interface OpenIdResponse {
  error_description: any;
  error: any;
  access_token: string;
  expires_in: number;
  refresh_expires_in: number;
  refresh_token: string;
  token_type: string;
  id_token: string;
  "not-before-policy": number;
  session_state: string;
  scope: string;
}

interface KeyCloakAccessTokenType {
  exp: number;
  iat: number;
  jti: string;
  iss: string;
  aud: string;
  sub: string;
  typ: string;
  azp: string;
  session_state: string;
  acr: string;
  "allowed-origins": string[];
  realm_access: real_access_type;
  resource_access: account;
  scope: string;
  sid: string;
  email_verified: true;
  name: string;
  preferred_username: string;
  given_name: string;
  family_name: string;
  email: string;
}

interface real_access_type {
  roles: string[];
}

interface account {
  roles: Array<any>;
}

interface RefreshTokenType {
  exp: number;
  iat: number;
  jti: string;
  iss: string;
  aud: string;
  sub: string;
  typ: string;
  azp: string;
  session_state: string;
  scope: string;
  sid: string;
}

interface KeyCloakHelperInterface {
  getToken(
    tenantMeta: TenantMeta,
    username: string,
    password: string
  ): Promise<OpenIdResponse>;
  login(
    tenantMeta: TenantMeta,
    username: string,
    password: string
  ): Promise<OpenIdResponse>;
  logout(tenantMeta: TenantMeta, refreshCookie: string): Promise<boolean>;
  refresh(
    tenantMeta: TenantMeta,
    refreshCookie: string | undefined
  ): Promise<OpenIdResponse>;
  convertParmsForBody(parms: object): string;
  getLoginForwardUrl(
    tenantMeta: TenantMeta,
    csrfCode: string,
    urlOrigin: string,
    email?: string
  ): string;
  exchangeOneTimeCodeForAccessToken(
    tenantMeta: TenantMeta,
    code: string,
    event: RequestEvent
  ): Promise<OpenIdResponse>;
  getByTenantName(tenantName: string | undefined): TenantMeta;
  getTenantByEmail(email: string): TenantMeta;
}

const emailValidator = (email: string): boolean => {
  // Credit to https://www.npmjs.com/package/email-validator
  const tester =
    /^[-!#$%&'*+\/0-9=?A-Z^_a-z`{|}~](\.?[-!#$%&'*+\/0-9=?A-Z^_a-z`{|}~])*@[a-zA-Z0-9](-*\.?[a-zA-Z0-9])*\.[a-zA-Z](-?[a-zA-Z0-9])+$/;
  if (!email) return false;
  const emailParts = email.split("@");
  if (emailParts.length !== 2) return false;
  const account = emailParts[0];
  const address = emailParts[1];
  if (account.length > 64) return false;
  else if (address.length > 255) return false;
  const domainParts = address.split(".");
  if (
    domainParts.some(function (part) {
      return part.length > 63;
    })
  )
    return false;
  if (!tester.test(email)) return false;
  return true;
};

const KeyCloakHelper: KeyCloakHelperInterface = {
  getToken: async (
    tenantMeta: TenantMeta,
    username: string,
    password: string
  ): Promise<OpenIdResponse> => {
    // Build OpenID Connect request body
    const postParms = {
      grant_type: "authorization_code",
      username: username,
      password: password,
      scope: "openid",
      client_id: tenantMeta.client_id,
      client_secret: tenantMeta.client_secret,
    } as object;
    const postParmsFormEncoded = new URLSearchParams(
      Object.entries(postParms)
    ).toString();

    try {
      const response = await fetch(
        `${KEYCLOAK_URL}/realms/${tenantMeta.realm}/protocol/openid-connect/auth`,
        {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: postParmsFormEncoded,
        }
      );
      return JSON.parse(await response.text()) as OpenIdResponse;
    } catch (err) {
      throw err;
    }
  },

  getLoginForwardUrl: (
    tenantMeta: TenantMeta,
    csrfCode: string,
    urlOrigin: string,
    email?: string
  ) => {
    const redirect_uri = `${urlOrigin}${LOGIN_PATH}/response`;

    const queryParameters = {
      response_type: "code",
      client_id: tenantMeta.client_id, // Route tenant for authentication to the correct realm!
      redirect_uri: redirect_uri,
      response_mode: "jwt",
      scope: "openid roles email profile",
      grant_type: "authorization_code",
      state: csrfCode,
      login_hint: !email ? "" : email,
    } as object;

    const queryString = Object.entries(queryParameters)
      .map(([key, value]) => {
        return `${key}=${encodeURIComponent(value)}`;
      })
      .join("&");

    // Redirect to Authentication Server
    return `${KEYCLOAK_URL}/realms/${tenantMeta.realm}/protocol/openid-connect/auth?${queryString}`;
  },

  login: async (
    tenantMeta: TenantMeta,
    username: string,
    password: string
  ): Promise<OpenIdResponse> => {
    // Not using this method... use this if you want to manage the complete login form in your app.

    // Build OpenID Connect request body
    const postParms = {
      grant_type: "password",
      username: username,
      password: password,
      scope: "openid",
      client_id: tenantMeta.client_id,
      client_secret: tenantMeta.client_secret,
    } as object;
    const postParmsFormEncoded = new URLSearchParams(
      Object.entries(postParms)
    ).toString();

    try {
      const response = await fetch(
        `${KEYCLOAK_URL}/realms/${tenantMeta.realm}/protocol/openid-connect/token`,
        {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: postParmsFormEncoded,
        }
      );
      return JSON.parse(await response.text()) as OpenIdResponse;
    } catch (err) {
      throw err;
    }
  },

  exchangeOneTimeCodeForAccessToken: async (
    tenantMeta: TenantMeta,
    oneTimeCode: string,
    event: RequestEvent
  ): Promise<OpenIdResponse> => {
    const postParmsFormEncoded = KeyCloakHelper.convertParmsForBody({
      client_id: tenantMeta.client_id,
      client_secret: tenantMeta.client_secret,
      redirect_uri: `${event.url.origin}${LOGIN_PATH}/response`,
      response_mode: "jwt",
      scope: "openid",
      grant_type: "authorization_code",
      code: oneTimeCode,
    });

    const response = await fetch(
      `${KEYCLOAK_INTERNAL_URL}/realms/${tenantMeta.realm}/protocol/openid-connect/token`,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: postParmsFormEncoded,
      }
    );

    const responseText = await response.text();
    const openIdResp = JSON.parse(responseText) as OpenIdResponse;

    return openIdResp;
  },

  refresh: async (
    tenantMeta: TenantMeta,
    refreshCookie: string | undefined
  ): Promise<OpenIdResponse> => {
    if (!refreshCookie) {
      throw new Error("No Refresh Token Found");
    }

    const postParms = {
      client_id: tenantMeta.client_id,
      client_secret: tenantMeta.client_secret,
      grant_type: "refresh_token",
      token_type_hint: "access_token",
      refresh_token: refreshCookie,
    } as object;
    const postParmsFormEncoded = new URLSearchParams(
      Object.entries(postParms)
    ).toString();

    try {
      const response = await fetch(
        `${KEYCLOAK_INTERNAL_URL}/realms/${tenantMeta.realm}/protocol/openid-connect/token`,
        {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: postParmsFormEncoded,
        }
      );
      return JSON.parse(await response.text()) as OpenIdResponse;
    } catch (err) {
      console.error(`Token Refresh Failed: ${err}}`);
      throw err;
    }
  },

  logout: async (
    tenantMeta: TenantMeta,
    refreshCookie: string
  ): Promise<boolean> => {
    var decoded = jwt.decode(refreshCookie) as RefreshTokenType;

    const postParms = {
      client_id: tenantMeta.client_id,
      client_secret: tenantMeta.client_secret,
      token_type_hint: "access_token",
      token: decoded.sid,
      grant_type: "refresh_token",
      refresh_token: refreshCookie,
    } as object;
    const postParmsFormEncoded = new URLSearchParams(
      Object.entries(postParms)
    ).toString();

    try {
      const response = await fetch(
        `${KEYCLOAK_INTERNAL_URL}/realms/${tenantMeta.realm}/protocol/openid-connect/logout`,
        {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: postParmsFormEncoded,
        }
      );

      return response.status === 204;
    } catch (err) {
      console.error("logout response error");
      throw err;
    }
  },

  getByTenantName: (tenantName: string | undefined): TenantMeta => {
    if (!tenantName) {
      throw new Error(`Tenant Name undefined`);
    }

    if (!tenants[tenantName.toLowerCase()]) {
      throw new Error(`Tenant ${tenantName} not found`);
    }

    return tenants[tenantName.toLowerCase()] as TenantMeta;
  },

  getTenantByEmail: (email: string): TenantMeta => {
    initTenantLookup(); // TODO: can do this conditionally later, for now forces reading file at login.
    const userEmailDomain = email.split("@")[1].toLowerCase();
    const thisTenant = Object.values(tenants).filter((value) => {
      return value.email_domain === userEmailDomain;
    });
    if (thisTenant.length === 0) {
      throw new Error(`No tenant matching ${email} domain`);
    }
    return thisTenant[0];
  },

  convertParmsForBody: (parmObj: object): string => {
    return new URLSearchParams(Object.entries(parmObj)).toString();
  },
};

const expireAuthCookies = (event: RequestEvent) => {
  [
    "AuthorizationToken",
    "RefreshToken",
    "IdToken",
    "LastPath",
    "csrfCode",
    "tenant",
  ].forEach((cookieName) => {
    event.cookies.set(cookieName, "", {
      httpOnly: true,
      path: "/",
      secure: true,
      sameSite: "strict",
      maxAge: 0,
    });
  });
};

interface KeyCloakHandleOptions {
  keycloakUrl: string;
  keycloakInternalUrl: string;
  loginPath: string;
  logoutPath: string;
}

const kcHandle: Handle = async ({ event, resolve }) => {
  const refreshTokenCookie = event.cookies.get("RefreshToken");
  //console.debug(`KeyCloak Handler fired for ${event.request.method} ${event.request.url}, RefreshToken: ${!!refreshTokenCookie}`);
  //console.debug(event);

  // Track the landing URL for the user when the come to the site so we can redirect them back there after login
  const pathIs = [LOGIN_PATH, `${LOGIN_PATH}/response`, LOGOUT_PATH];
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
    throw redirect(302, LOGIN_PATH);
  }

  // Don't execute code past this if there is no refresh token and user is on the login page
  if (
    !refreshTokenCookie &&
    event.url.pathname === LOGIN_PATH &&
    event.request.method === "GET"
  ) {
    // If no CSRF cookie, create one for the /login/response validation
    // console.log('2: !refreshTokenCookie && event.url.pathname === LOGIN_PATH && event.request.method === GET');
    const csrfCode = event.cookies.get("csrfCode");
    if (!csrfCode) {
      // console.log('No CSRF cookie, creating one');
      const clientCode = cryptoRandomString({ length: 16, type: "url-safe" });
      event.cookies.set("csrfCode", clientCode, {
        httpOnly: true,
        path: "/",
        secure: true,
        sameSite: "strict",
        maxAge: 60 * 5, // 5 minute duration for the CSRF cookie
      });
    }

    return await resolve(event);
  }

  if (
    event.url.pathname === LOGIN_PATH &&
    event.request.method === "POST" &&
    event.url.search === "?/login"
  ) {
    // console.log('3: event.url.pathname === LOGIN_PATH && event.request.method === POST && event.url.search === ?/login');
    const data = await event.request.formData();
    const email = data.get("email")?.toString();
    const validEmail = !!email ? emailValidator(email) : false;
    if (!validEmail || !email) {
      console.error(`Invalid email address: ${email}`);
      throw redirect(303, `${LOGIN_PATH}?err=invalidemail`);
    }
    const csrfCode = event.cookies.get("csrfCode");
    if (!csrfCode) {
      throw redirect(303, LOGIN_PATH);
    }
    let loginUrl = "";
    try {
      const tenantMeta = KeyCloakHelper.getTenantByEmail(email);
      loginUrl = KeyCloakHelper.getLoginForwardUrl(
        tenantMeta,
        csrfCode,
        event.url.origin,
        email
      );
    } catch (err) {
      console.error(
        `Keycloakservice login error. Client: ${event.getClientAddress()}, Error: ${err}`
      );
      throw redirect(303, LOGIN_PATH);
    }
    throw redirect(303, loginUrl);
  }

  if (event.url.pathname === `${LOGIN_PATH}/response`) {
    // console.log('4: event.url.pathname === ${LOGIN_PATH}/response');
    // Ensure the response includes the auth code in the query string
    let loginResponse = event.url.searchParams.get("response");
    if (!loginResponse) {
      expireAuthCookies(event);
      throw redirect(302, LOGIN_PATH);
    }
    const decoded = jwt.decode(loginResponse) as any;

    // Ensure CSRF Code from the client cookie matches what is in the response header
    const csrfCode = event.cookies.get("csrfCode");
    if (decoded.state !== csrfCode) {
      console.error("CSRF Code Mismatch! Do not trust this response!");
      expireAuthCookies(event);
      event.locals.user = null;
      throw redirect(302, LOGIN_PATH);
    }

    if (!decoded.iss) {
      console.error('No "iss" in response, reqiured to get tenant/realm.');
      throw redirect(302, LOGIN_PATH);
    }

    // Convert one-time access code for access token
    try {
      const tenantName = decoded.iss.split("/realms/")[1];
      const tenantMeta = KeyCloakHelper.getByTenantName(tenantName);
      const openIdResp = await KeyCloakHelper.exchangeOneTimeCodeForAccessToken(
        tenantMeta,
        decoded.code,
        event
      );

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

      const accessToken = jwt.decode(
        openIdResp.access_token
      ) as KeyCloakAccessTokenType;
      event.locals.user = {
        loggedIn: true,
        username: accessToken.name,
        email: accessToken.email,
        tenant: tenantMeta.name,
        roles: accessToken.realm_access.roles,
      };
    } catch (err) {
      console.error(`Unable to Obtain Access Code from One-Time-use Code`);
      console.error(err);
      expireAuthCookies(event);
      event.locals.user = null;
      throw redirect(302, LOGIN_PATH);
    }

    // Redirect user back to their original path pre-login
    const LastPath = event.cookies.get("LastPath");
    throw redirect(302, !LastPath ? "/" : LastPath);
  }

  // Don't execute code past this if there is no refresh token and user is on the login page
  if (!refreshTokenCookie && event.url.pathname === LOGOUT_PATH) {
    // console.log('5: !refreshTokenCookie && event.url.pathname === LOGOUT_PATH');
    return await resolve(event);
  }

  // Require valid tenant metadata to continue
  // console.log('6: Refresh Token JWT required to continue');
  const decoded = jwt.decode(refreshTokenCookie ?? "") as any;
  const tenantName = (decoded.iss ?? "").toLowerCase().split("/realms/")[1];
  const tenantMeta = KeyCloakHelper.getByTenantName(tenantName);
  if (!tenantMeta) {
    expireAuthCookies(event);
    event.locals.user = null;
    throw redirect(302, LOGIN_PATH);
  }

  // If we have a refresh token on normal page loads if possible
  if (refreshTokenCookie && pathIs.indexOf(event.url.pathname) === -1) {
    // console.log('7: Valid Refresh Token if not on login/loginreponse/logout route');
    try {
      const refreshMeta = await KeyCloakHelper.refresh(
        tenantMeta,
        refreshTokenCookie
      );
      event.cookies.set("RefreshToken", refreshMeta.refresh_token, {
        httpOnly: true,
        path: "/",
        secure: true,
        sameSite: "strict",
        maxAge: refreshMeta.refresh_expires_in,
      });

      if (refreshMeta.error) {
        // Note: this will set the short term CSRF cookie on landing at /auth/login when hooks.server.ts is invoked again
        console.error(
          `KeyCloakService: Token Refresh Failed. Clear cookies return to login page. Message: ${refreshMeta.error_description}`
        );
        event.cookies.set("RefreshToken", "", {
          httpOnly: true,
          path: "/",
          secure: true,
          sameSite: "strict",
          maxAge: 0,
        });
        event.locals.user = null;
        throw redirect(302, LOGIN_PATH);
      }

      // Set the user information in a variable that can be accessed by other pages
      const accessMeta = jwt.decode(
        refreshMeta.access_token
      ) as KeyCloakAccessTokenType;

      event.locals.user = {
        loggedIn: true,
        username: accessMeta.name,
        email: accessMeta.email,
        tenant: tenantMeta.name,
        roles: accessMeta.realm_access.roles,
      };

      const response = await resolve(event);
      return response;
    } catch (err) {
      // Note: this will set the short term CSRF cookie on landing at /login when hooks.server.ts is invoked again
      expireAuthCookies(event);
      event.locals.user = null;
      throw redirect(302, LOGIN_PATH);
    }
  }

  if (refreshTokenCookie && event.url.pathname === LOGOUT_PATH) {
    // console.log('8: Has refresh token and on logout route');
    try {
      await KeyCloakHelper.logout(tenantMeta, refreshTokenCookie);
    } catch (err) {
      console.error(`Logout Failed! ${err}`);
    }

    expireAuthCookies(event);
    event.locals.user = null;

    // Reset the CSRF cookie to a new value in case the user wants to log back in
    const clientCode = cryptoRandomString({ length: 16, type: "url-safe" });
    event.cookies.set("csrfCode", clientCode, {
      httpOnly: true,
      path: "/",
      secure: true,
      sameSite: "strict",
      maxAge: 60 * 5, // 5 minute duration for the CSRF cookie
    });

    await resolve(event);
    throw redirect(302, LOGOUT_PATH);
  }

  // console.log('9: Fell through logic, resolving');

  return await resolve(event);
};

const KeyCloakHandle = (config: KeyCloakHandleOptions): Handle => {
  KEYCLOAK_URL = config.keycloakUrl;
  KEYCLOAK_INTERNAL_URL = config.keycloakInternalUrl;
  LOGIN_PATH = config.loginPath;
  LOGOUT_PATH = config.logoutPath;
  return kcHandle;
};

export { KeyCloakHandle, emailValidator, type UserInfo };
