# USACE Keycloak JS v2

> Minimal, modern Keycloak authentication and token management for browser apps.

**NPM Package:** [`@usace/keycloak`](https://www.npmjs.com/package/@usace/keycloak)  
**Version:** `2.0.1`

## Installation

```sh
npm install @usace/keycloak
```

Or with yarn:

```sh
yarn add @usace/keycloak
```

## Import

```js
import Keycloak, { tokenToObject } from "@usace/keycloak";
```

## Quick Start

```js
import Keycloak from "@usace/keycloak";

const kc = new Keycloak({
  client: "my-client",
  keycloakUrl: "https://identity.sec.usace.army.mil/auth",
  realm: "cwbi",
  redirectUrl: window.location.origin + "/callback",
  onAuthenticate: (token, keycloakResponse) => {
    // User is authenticated, do something with token!
    console.log("Access Token:", token);
  },
  onSessionEnding: (secondsLeft) => {
    alert(`Your session will expire in ${secondsLeft} seconds.`);
  },
  onError: (err) => {
    alert("Keycloak error: " + err);
  },
});

// To start login:
kc.authenticate();

// On callback route, handle token exchange:
kc.checkForSession();
```

---

## Configuration Options

Pass these as an object to the `Keycloak` constructor:

| Option              | Type     | Default          | Description                                                                          |
| ------------------- | -------- | ---------------- | ------------------------------------------------------------------------------------ |
| `client`            | string   | —                | Keycloak client ID (required)                                                        |
| `keycloakUrl`       | string   | —                | Base URL to Keycloak instance (required)                                             |
| `realm`             | string   | —                | Realm name (required)                                                                |
| `redirectUrl`       | string   | —                | URL to redirect after login (required)                                               |
| `logoutUrl`         | string   | `keycloakUrl`    | Base Keycloak URL for logout (defaults to `keycloakUrl` if not set)                  |
| `directGrantUrl`    | string   | `keycloakUrl`    | URL for direct grant/token endpoint                                                  |
| `browserFlowUrl`    | string   | `keycloakUrl`    | URL for browser login flow                                                           |
| `refreshUrl`        | string   | `keycloakUrl`    | URL for refresh endpoint                                                             |
| `kc_idp_hint`       | string   | "login.gov"      | Identity provider hint                                                               |
| `scope`             | string   | "openid profile" | OAuth scopes                                                                         |
| `refreshInterval`   | number   | (from token)     | Override refresh interval (seconds)                                                  |
| `refreshBuffer`     | number   | 60               | Buffer (seconds) before token expiry to refresh                                      |
| `sessionEndWarning` | number   | 60               | Warn user (seconds) before session expiry                                            |
| `accessToken`       | string   | —                | Initial access token, if known                                                       |
| `identityToken`     | string   | —                | Initial identity token, if known                                                     |
| `refreshToken`      | string   | —                | Initial refresh token, if known                                                      |
| **Callbacks:**      |          |                  |                                                                                      |
| `onAuthenticate`    | function | —                | Called after authentication/refresh with access token and the full keycloak response |
| `onSessionEnding`   | function | —                | Called before session expiry (seconds left)                                          |
| `onError`           | function | throws Error     | Called on authentication error                                                       |
| `onLogout`          | function | —                | Called after programmatic logout (non-redirect)                                      |

---

## API Reference

### Constructor

```js
const kc = new Keycloak(options);
```

---

### `authenticate(overrides)`

Redirects the browser to the Keycloak login page to initiate the browser authentication flow.

**Parameters:**
- `overrides` (optional): Object to override configuration at runtime
  - `realm` - Override the realm for this authentication
  - `kc_idp_hint` - Override the identity provider hint (e.g., "login.gov", "federation-eams")
  - `redirectUrl` - Override the redirect URL after authentication

```js
// Standard authentication using configured values
kc.authenticate();

// Override realm and IDP for this login
kc.authenticate({
  realm: "different-realm",
  kc_idp_hint: "federation-eams",
  redirectUrl: "https://myapp.com/custom-callback"
});
```

**Use Cases:**
- Switch between different identity providers (login.gov vs federation-eams) based on user choice
- Use different redirect URLs depending on where the user initiated login
- Authenticate to different realms dynamically

---

### `checkForSession()`

Checks the current URL for an authorization code, exchanges it for tokens, and triggers `onAuthenticate`.

```js
kc.checkForSession();
```

> **Call this on your redirect/callback page after login!**

---

### `refresh()`

Refreshes the access token using the refresh token, if available.

```js
kc.refresh();
```

---

### `directGrantAuthenticate(user, pass)`

Logs in using the OAuth2 "Resource Owner Password" grant.
**Not recommended for browser use unless strictly required.**

```js
kc.directGrantAuthenticate("username", "password");
```

---

### `directGrantX509Authenticate(overrides)`

Attempts to authenticate using X.509 client certificate to implement AJAX based CAC auth.

**Parameters:**
- `overrides` (optional): Object to override configuration at runtime
  - `realm` - Override the realm for this authentication
  - `scope` - Override the OAuth scopes for this authentication

```js
// Standard X.509 authentication using configured values
kc.directGrantX509Authenticate();

// Override realm and scope
kc.directGrantX509Authenticate({
  realm: "cwbi-cac",
  scope: "openid profile email"
});
```

> Note when using CWBI Keycloak, `https://identity...` does not parse the CAC certificate, `https://identityc...` will parse the CAC certificate. For the best user experience, use the `c` endpoint as the `directGrantUrl` and the non-c endpoint as the `keycloakUrl` so the user is not prompted for CAC pin when refreshing tokens.

---

### `getAccessToken()` / `getIdentityToken()`

Get the most recently stored tokens:

```js
const accessToken = kc.getAccessToken();
const idToken = kc.getIdentityToken();
```

---

### `logout({ redirect = true } = {})`

Log out of Keycloak.

- **redirect** (default `true`): redirect the browser to Keycloak’s logout endpoint (recommended for browser SSO).
- If `redirect` is false, uses a back-channel (POST) logout.

```js
// Redirect to logout page (user logged out everywhere):
kc.logout(); // or kc.logout({redirect: true})

// Programmatic logout (no redirect, just token revocation):
kc.logout({ redirect: false });
```

---

### Token Parsing Utility

```js
import { tokenToObject } from "@usace/keycloak";

// Decode JWT access or ID token to a JS object:
const payload = tokenToObject(accessToken);
console.log(payload.sub); // user id
```

---

## Callback Hooks

Provide these as options to the constructor for more control:

- **onAuthenticate(token | { accessToken, identityToken, refreshToken })**
  Called after successful authentication or token refresh.

- **onSessionEnding(secondsLeft)**
  Warn the user when their session is about to expire.

- **onError(error)**
  Handles any error from authentication or token refresh.

- **onLogout()**
  Called after a non-redirecting logout completes.

---

## Usage Examples

### 1. Standard Login Flow

```js
const kc = new Keycloak({...});
kc.authenticate();
// ... user logs in, Keycloak redirects to your redirectUrl ...
kc.checkForSession();
```

---

### 2. Dynamic Identity Provider Selection

```js
// Let users choose their login method
function loginWithLoginGov() {
  kc.authenticate({ kc_idp_hint: "login.gov" });
}

function loginWithEAMS() {
  kc.authenticate({ kc_idp_hint: "federation-eams" });
}
```

---

### 3. Context-Aware Redirects

```js
// Redirect back to the current page after login
function loginHere() {
  kc.authenticate({
    redirectUrl: window.location.href
  });
}
```

---

### 4. Refresh Token on Demand

```js
setInterval(() => {
  kc.refresh();
}, 10 * 60 * 1000); // every 10 minutes (optional, as refresh is handled automatically)
```

---

### 5. Decode Token Claims

```js
const info = tokenToObject(kc.getAccessToken());
console.log(info.email, info.preferred_username);
```

---

## Best Practices & Notes

- **Always call `kc.checkForSession()` on your redirect URI after login when using browser flow.**
- **The library automatically schedules token refreshes before expiry.**
- **Configure valid redirect URIs for your Keycloak client.**
- **Never expose client secrets in client-side code.**
- **Do not use the username/password direct grant flow unless necessary.**
- **Handle errors in the `onError` callback.**

---

## Release Notes

**Version 2.1.0**

- Added runtime overrides support to `authenticate()` method
  - Override `realm`, `kc_idp_hint`, and `redirectUrl` at runtime
  - Enables dynamic identity provider selection
  - Supports context-aware redirect URLs
- Added runtime overrides support to `directGrantX509Authenticate()` method
  - Override `realm` and `scope` at runtime
- Improved `logoutUrl` configuration with fallback to `keycloakUrl` for consistency

**Version 2.0.0**

- Complete refactor for clarity and modern browser flows
- Cleaner API and callback pattern
- Improved error handling
- Should be backwards compatible with 1.x releases, but not guaranteed.

---

## License

MIT (or your organization’s standard license)

---

```

Let me know if you want to tweak any section or add badges, CI, or advanced troubleshooting!
```
