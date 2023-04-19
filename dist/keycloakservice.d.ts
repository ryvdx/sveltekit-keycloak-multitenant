import { type Handle } from "@sveltejs/kit";
interface UserInfo {
    username: string;
    email: string;
    loggedIn: boolean;
    roles: string[];
    tenant: string;
}
declare const emailValidator: (email: string) => boolean;
interface KeyCloakHandleOptions {
    keycloakUrl: string;
    keycloakInternalUrl: string;
    loginPath: string;
    logoutPath: string;
    postLoginPath?: string;
}
declare const KeyCloakHandle: (config: KeyCloakHandleOptions) => Handle;
export { KeyCloakHandle, emailValidator, type UserInfo };
