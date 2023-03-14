# sveltekit-keycloak-multitenant
For adding multi-tenant authentication and authorization in SvelteKit apps using KeyCloak.


# Motivation


# Setup

```
npm install -i sveltkit-keycloak-multitenant
```

1. Setup .ENV variables

This module requires these 5 variables specified in your .env file of your sveltekit app.
| Variable      | Purpose      | Example (Default)  |
| ------------- |--------------| ------|
| KEYCLOAK_URL  | URL of your Keycloak server taking OIDC calls. | http://localhost:8085 |
| LOGIN_PATH    | Where the login form will be and unauthenticated users will automatically be redirected to. | /auth/login  |
| LOGOUT_PATH   | path where you want to redirect to post logout.  Must be an SSR page. (route has a +page.server.ts/js file) | /auth/logout |
| TENANT_YAML   | Absolute path to where tenant YAML file is.  (So it can be injected as a container dependency.)    | (some absolute path) |


