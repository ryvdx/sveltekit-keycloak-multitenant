# sveltekit-keycloak-multitenant

Multi-tenant (fully federated) authentication and authorization library for KeyCloak in SvelteKit apps.
Enables role-based-access-controls configuration in Keycloak, and SvelteKit app role metadata access in SSR.
Uses a Hybrid Authentication flow and JWT tokens.

# Motivation

Needed a solution for multitenant authentication in a SvelteKit app intended to run in a containerized environment.
Intended for apps that need fully federated authentication (i.e. enterprise B2B apps serving customers with varying authentication requirements.)
Most auth solutions are single-tenant, including most keycloak libraries for sveltekit.

This library enables apps to use multiple keycloak realms mapping customer user email domains to realms.

1. Each customer has fully configurable authentication per their enterprise reqiurements.
   (i.e. bring-your-own-identity-provider, 2-factor Auth for others, different authentication rules for every customer)
2. Roles and Role-based-access-controls configuration done entirely in Keycloak, simplify complexity of managing multitenancy within your app.
3. Easy to add new tenants at run-time using a simple externally loaded dependancy. (Yaml file that maps email domains to realms.)

Some added benefits of this library:

- Single implementation in hooks.server.ts handles all routes and API calls
- Low-client trust: HTTP-only strict domain cookies used. No access tokens shared with client.  Code exchange for access tokens, token refresh, logout kept in secure network between containers.

# Install
```
yarn install -S sveltkit-keycloak-multitenant
```

# SvelteKit App Summary
See example: https://github.com/ryvdx/sveltekit-keycloak-multitenant-example  (/demoapp)
1. Setup .ENV variables
2. add userinfo definition in app.d.ts locals
3. Add KeyCloakHandle to src/hooks.server.ts file
4. Make a basic login form
5. Make a Logout route (must have +page.server file to force SSR)
6. Integrate your navigation and logout into layout.server.ts

(Remainder can be setup outside of your app.  See docker-compose in root and Readme in example link above.)

# Keycloak Library Integration Details

## 1. Setup .ENV variables

| Variable              | Purpose                                                                                                  | Example (Default)     |
| --------------------- | -------------------------------------------------------------------------------------------------------- | --------------------- |
| KEYCLOAK_URL          | URL of your Keycloak server taking OIDC authentication calls.                                            | https://auth.myapp   |
| KEYCLOAK_INTERNAL_URL | Intenal URL of your Keycloak server within containerized network.                                        | http://keycloak:8085  |
| LOGIN_PATH            | Relative path to user email form pre-login.                                                              | /auth/login           |
| LOGOUT_PATH           | path where you want to redirect to post logout. (Route must have a server side +page.server.ts/js file)  | /auth/logout          |
| POST_LOGIN_PATH       | (Optional) post authentication redirect if initial landing was not a deep link. (default / if not set)   | /homepage             |

## 2. add userinfo definition in app.d.ts locals

User info and user roles is stored in locals by hooks.server.ts.

```
// See https://kit.svelte.dev/docs/types#app
/// <reference types="@auth/sveltekit" />
import type { UserInfo } from '$lib/server/keycloakservice';

declare global {
	namespace App {
		interface Locals {
			user: UserInfo | null,
		}
	}
}

export {};
```

## 3. Add handler to hooks.server.ts file

```
import type { Handle } from "@sveltejs/kit";
import { KeyCloakHandle } from "sveltekit-keyloak-multitenant";
import { env } from "$env/dynamic/private";

export const handle: Handle = KeyCloakHandle({
    keycloakUrl: env.KEYCLOAK_URL,
    keycloakInternalUrl: env.KEYCLOAK_INTERNAL_URL,
    loginPath: env.LOGIN_PATH,
    logoutPath: env.LOGOUT_PATH,
    postLoginPath: env.POST_LOGIN_PATH,
  });
```

Alternatively if you have other hooks middleware functions:

```
import { sequence } from '@sveltejs/kit/hooks';
import type { Handle } from "@sveltejs/kit";
import { KeyCloakHandle } from "sveltekit-keyloak-multitenant";
import { env } from "$env/dynamic/private";

export const handle: Handle = sequence(
  KeyCloakHandle({
    keycloakUrl: env.KEYCLOAK_URL,
    keycloakInternalUrl: env.KEYCLOAK_INTERNAL_URL,
    loginPath: env.LOGIN_PATH,
    logoutPath: env.LOGOUT_PATH,
    postLoginPath: env.POST_LOGIN_PATH,
  }),
);
```

## 4. Make a basic login form

Define a route that matches the ENV variable LOGIN_PATH that includes the basic email submission form.
KeyCloakHandle will map the user to a tenant using email (domain), and redirect the user to the appropriate realm for authenication.
Will also pass the email to the authentication for convenience so user does not have to specify that twice.

Form requirements:
- input with type=email and name=email
- post action="?/login"  (KeyCloakHandle handle will intercept, +page.server.ts not required for LOGIN_PATH)

```
  <form method="post" action="?/login">
      <label for="email">email</label>
      <input type="email" name="email" />
      <button>Sign In</button>
  </form>
```

## 5. Make a Logout route

Implement a route LOGOUT_PATH is going to be set to. 
This route must have +page.svelte AND +page.server.ts (to force server-side after logout)
No logic required in +page.server file, and customize +page.svelte for whatever logout message your want.

## 6. Integrate the navigation and logout into layout.server.ts

Pass through locals variables out as page data in +layout.server.ts.
(Note, for pages that hide/show features within the page by role, you can pass the UserInfo object to the page renderer in that pages load method as well.)

```
import type { LayoutServerLoad } from "./$types"

export const load: LayoutServerLoad = async (event) => {

  return {
    user: event.locals.user,
  }
}
```

Example +layout.svelte file. (You can do anything with the UserInfo metadata returned in the laste step.) This shows:

- protected route rendering for authenticated users
- rendering of special routes based on custom roles you define in KeyCloak
- (No rendering for unauthenticated/logged-out user. Will just render the content defined by LOGIN_PATH route in the slot.)

```
<script lang="ts">
    import type { PageData } from './$types';
    export let data: PageData;
</script>

<nav>
    {#if data.user}
        <span>Welcome: {data.user.username}</span>
        <span>tenant: {data.user.tenant}</span>
        <a href="/">Home</a>
        <a href="/protectedRoute1">Some Protected Route</a>
        <a href="/protectedRoute2">Another Protected Route</a>
        {#if data.user.roles && data.user.roles.includes('admin')}
            <a href="/admin">Admin</a>
        {/if}
        <a href="/auth/logout" data-sveltekit-preload-data="off">Logout</a>
    {/if}
</nav>

<slot />

<style>
    ... your style here ...
</style>
```

# Important:
data-sveltekit-preload-data="off" required on logout link along with the +page.server file for the LOGOUT_PATH.
This ensures a server side response to the logout.  This will end the user session in Keycloak, clear the locals, which then lets your Layout files update using an unauthenticated sate.  On logout, when page returns to client, it will expire the refresh cookie and any other cookies.

# Tenants.yaml file

System runs using a YAML configuration file declaring tenants.  Users mapped to realms using email domains.
If email domain / tenant mapping does not exist, it will re-read the yaml file and try again.  (Enables quick edit of the file and injected/updated on the fly.)
Note: do not use "master" realm for customer apps per Keycloak best practices.  Create per-customer new realms.
(For setup of KeyCloak, see https://github.com/ryvdx/sveltekit-keycloak-multitenant-example)


```
mustangs:
  client_id: 'webapp'
  client_secret: 'yourclientsecrethere'
  realm: 'mustangs'
  email_domain: 'mustangs.com'
camaros:
  client_id: 'webapp'
  client_secret: 'yourclientsecrethere'
  realm: 'camaros'
  email_domain: 'camaros.io'
```

Optional: Extend this with any additional metadata to customize your per-tenant experience:

```
mustangs:
  client_id: 'webapp'
  client_secret: 'yourclientsecrethere'
  realm: 'mustangs'
  email_domain: 'mustangs.com'
  customer_logo: '',
  default_locale: 'en-US'
```

Note: If you want type support for those attributes in +layout.svelte/+page.svelte, you can extend the definition in app.d.ts:

```
import type { UserInfo } from '$lib/server/keycloakservice';

interface MyAppUserInfo extends UserInfo {
    customer_logo:string;
    default_locale:string;
}

declare global {
	namespace App {
		interface Locals {
			user: MyAppUserInfo | null,
		}
	}
}

export {};
```
