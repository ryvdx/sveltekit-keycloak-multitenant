# sveltekit-keycloak-multitenant
For adding multi-tenant authentication and authorization in SvelteKit apps using KeyCloak.


# Motivation
Wanted to find a cost effective solution for multitenant authentication in SvelteKit apps.  Most solutions and online examples are built for single-tenancy, or quickly expanding on authentication providers and social logins.  (B2C apps)

Keycloak is multitenant out of the box, open source, easy to containerize and put behind a reverse proxy, and supports a diverse capaility set for authentication configuration. (i.e. bring-your-own-identity-provider, 2-factor Auth, escoteric authentication methods like keycards or face/fingerprint recognition, different password rules for others still.)  I wanted the extensibility that Keycloak provided, but solutions/examples online I found where implemented as single tenant. (i.e. one realm and one client adapter supported.)

This library enables apps to use multiple keycloak realms using email domains for federated authentication services. (B2B apps)

1. Each customer has fully configurable authentication per their enterprise reqiurements.
    (i.e. bring-your-own-identity-provider, 2-factor Auth for others, different authentication rules for every customer)
2. Roles and Role-based-access-controls configuration done entirely in Keycloak, simplify complexity of managing multitenancy within your app.
3. Easy to add new tenants at run-time.

# Install
```
npm install -i sveltkit-keycloak-multitenant
```
# Setup

1. Setup .ENV variables
2. add userinfo definition in app.d.ts locals
3. Add handler to hooks.server.ts file
4. Make a basic login form
5. Integrate the navigation and logout into layout.server.ts
6. Setup Keycloak
7. Update tenants.yaml with the tenants and clients setup in the last step

# Setup Walkthrough

## 1. Setup .ENV variables[1. Setup .ENV variables]

| Variable      | Purpose      | Example (Default)  |
| ------------- |--------------| ------|
| KEYCLOAK_URL  | URL of your Keycloak server taking OIDC calls. | http://localhost:8085 |
| LOGIN_PATH    | Where the login form will be and unauthenticated users will automatically be redirected to. | /auth/login  |
| LOGOUT_PATH   | path where you want to redirect to post logout.  Must be an SSR page. (route has a +page.server.ts/js file) | /auth/logout |
| TENANT_YAML   | Absolute path to where tenant YAML file is.  (So it can be injected as a container dependency.)    | (some absolute path) |

[## 2. add userinfo definition in app.d.ts locals](## 2. add userinfo definition in app.d.ts locals)
User info is stored in locals by hooks.server.ts.

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
import { KeyCloakHandle } from "$lib/server/keycloakservice";

export const handle: Handle = KeyCloakHandle;
```

Or, if you have multiple handle functions running in all server-side calls, you can use sequence.
```
import { sequence } from '@sveltejs/kit/hooks';
import type { Handle } from "@sveltejs/kit";
import { KeyCloakHandle } from "$lib/server/keycloakservice";

export const handle: Handle = sequence(
  KeyCloakHandle,
  // Your other handle functions here...
);
```

## 4. Make a basic login form
Define a route that matches the ENV variable LOGIN_PATH that includes the basic email submission form.
KeyCloakHandle will map the user to a tenant using email (domain), and redirect the user to the appropriate realm for authenication.
Will also pass the email to the authentication for convenience so user does not have to specify that twice.

Form requires:
- input with type=email and name=email
- post action="?/login"

```
<script lang="ts"></script>

<div>
    <form method="post" action="?/login">
        <label for="email">email</label>
        <input type="email" name="email" />
        <button>Sign In</button>
    </form>
</div>

<style>
    ... your style here ...
<style>

```

## 5. Integrate the navigation and logout into layout.server.ts

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

Example +layout.svelte file.  (You can do anything with the UserInfo metadata returned in the laste step.) This shows:
- protected route rendering for authenticated users
- rendering of special routes based on custom roles you define in KeyCloak
- (No rendering for unauthenticated/logged-out user.   Will just render the content defined by LOGIN_PATH route in the slot.)

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

## 6. Setup Keycloak


## 7. Update tenants.yaml with the tenants and clients setup in the last step
Structure your metadata as follows... the key in the first level is the assumed "tenant name".
(Might do this different in the future an leverage a service account in the master realm to get all this,
for now this is simple enough.  Easy enough to update the dependency in a container in Kubernetes or Docker.
login route will try to refresh pulling this so the lookupt won't get out-of-sync if the file is updated.)

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

Note you can extend this however you want, add a customer logo attribute or whatever.  Anything in this will be available in the locals.

```
mustangs:
  client_id: 'webapp'
  client_secret: 'yourclientsecrethere'
  realm: 'mustangs'
  email_domain: 'mustangs.com'
  customer_logo: '',
  default_locale: 'en-US'
```

If you add custom tenant attributes, extend the UserInfo type in app.d.ts so you have type support in your +layout.svelte/+page.svelte files:
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
