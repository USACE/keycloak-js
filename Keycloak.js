const urlencodeFormData = (fd) => new URLSearchParams([...fd]);
const pkceStatePrefix = "usace-keycloak:pkce:";
const pkceMaxAgeMs = 15 * 60 * 1000;

const randomBase64Url = (byteCount) => {
  const bytes = new Uint8Array(byteCount);
  window.crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
};

const createPkcePair = async () => {
  if (!window.crypto?.getRandomValues || !window.crypto?.subtle) {
    throw new Error("PKCE requires the Web Crypto API in a secure browser context");
  }
  const verifier = randomBase64Url(32);
  const digest = await window.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier)
  );
  const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return { verifier, challenge };
};

class Keycloak {
  constructor(opts) {
    // default values
    const defaults = {
      accessToken: undefined,
      client: undefined,
      identityToken: undefined,
      kc_idp_hint: "login.gov",
      keycloakUrl: undefined,
      directGrantUrl: undefined,
      browserFlowUrl: undefined,
      logoutUrl: undefined,
      redirectUrl: undefined,
      refreshUrl: undefined,
      realm: undefined,
      refreshToken: undefined,
      refreshInterval: undefined, // if configured will override interval returned by keycloak
      refreshBuffer: 60, // 1 minute in seconds
      sessionEndWarning: 60, // 1 minute in seconds
      scope: "openid profile",
      pkceMethod: "S256",

      onSessionEnding: undefined,
      onAuthenticate: undefined,
      onError: (msg) => {
        throw new Error(`Keycloak-js Error: ${msg}`);
      },
      onLogout: undefined,
    };

    const config = { ...defaults, ...opts };

    this.accessToken = config.accessToken;
    this.client = config.client;
    this.code = undefined;
    this.identityToken = config.identityToken;
    this.kc_idp_hint = config.kc_idp_hint;
    this.keycloakUrl = config.keycloakUrl;
    this.directGrantUrl = config.directGrantUrl || config.keycloakUrl;
    this.browserFlowUrl = config.browserFlowUrl || config.keycloakUrl;
    this.logoutUrl = config.logoutUrl || config.keycloakUrl;
    this.redirectUrl = config.redirectUrl;
    this.refreshUrl = config.refreshUrl || config.keycloakUrl;
    this.realm = config.realm;
    this.refreshToken = config.refreshToken;
    this.refreshInterval = config.refreshInterval;
    this.refreshBuffer = config.refreshBuffer;
    this.sessionState = undefined;
    this.sessionTimeout = undefined;
    this.sessionEndWarning = config.sessionEndWarning;
    this.scope = config.scope;
    if (config.pkceMethod !== "S256" && config.pkceMethod !== false) {
      throw new Error('pkceMethod must be "S256" or false');
    }
    this.pkceMethod = config.pkceMethod;

    this.onSessionEnding = config.onSessionEnding;
    this.onAuthenticate = config.onAuthenticate;
    this.onError = config.onError;
    this.onLogout = config.onLogout;
  }

  authenticate(overrides = {}) {
    // allow run-time overrides of some of the config
    // this lets you switch between login.gov or eams-a for the
    // browser flow or use a different redirect url depending
    // on where a user is when they login.
    const realm = overrides.realm || this.realm;
    const kc_idp_hint = overrides.kc_idp_hint || this.kc_idp_hint;
    const redirectUrl = overrides.redirectUrl || this.redirectUrl;

    try {
      const url = new URL(
        `${this.browserFlowUrl}/realms/${realm}/protocol/openid-connect/auth`
      );
      url.searchParams.set("response_type", "code");
      url.searchParams.set("kc_idp_hint", kc_idp_hint);
      url.searchParams.set("client_id", this.client);
      url.searchParams.set("scope", "openid");
      url.searchParams.set("redirect_uri", redirectUrl);
      url.searchParams.set("nocache", new Date().getTime());

      if (!this.pkceMethod) {
        window.location.href = url.toString();
        return;
      }

      // Web Crypto is asynchronous. Keep the existing fire-and-forget login call;
      // navigate only after the challenge and matching verifier are ready.
      return createPkcePair()
        .then(({ verifier, challenge }) => {
          const state = randomBase64Url(32);
          window.sessionStorage.setItem(
            pkceStatePrefix + state,
            JSON.stringify({ verifier, realm, redirectUrl, createdAt: Date.now() })
          );
          url.searchParams.set("state", state);
          url.searchParams.set("code_challenge", challenge);
          url.searchParams.set("code_challenge_method", "S256");
          window.location.href = url.toString();
        })
        .catch((error) => this.onError(error));
    } catch (error) {
      this.onError(error);
    }
  }

  checkForSession() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get("code");
    const error = urlParams.get("error");
    if (!code && !error) return;

    try {
      let transaction;
      if (this.pkceMethod) {
        const state = urlParams.get("state");
        if (!state) throw new Error("Missing authorization state");
        const stored = window.sessionStorage.getItem(pkceStatePrefix + state);
        if (!stored) throw new Error("Unknown or already used authorization state");
        window.sessionStorage.removeItem(pkceStatePrefix + state);
        transaction = JSON.parse(stored);
        if (
          !transaction.verifier || !transaction.realm || !transaction.redirectUrl ||
          !Number.isFinite(transaction.createdAt) ||
          Date.now() - transaction.createdAt > pkceMaxAgeMs ||
          transaction.createdAt > Date.now()
        ) {
          throw new Error("Invalid or expired authorization state");
        }
      }

      if (error) {
        throw new Error(`Authorization failed: ${error}`);
      }
      this.code = code;
      this.sessionState = urlParams.get("session_state");
      this.codeFlowAuth(transaction);
    } catch (authError) {
      this.onError(authError);
    } finally {
      const url = new URL(window.location.href);
      for (const name of ["code", "state", "session_state", "iss", "error", "error_description"]) {
        url.searchParams.delete(name);
      }
      window.history.replaceState(null, "", url.pathname + url.search + url.hash);
    }
  }

  _getRefreshInterval(expiresIn) {
    if (this.refreshInterval) {
      return this.refreshInterval * 1000;
    } else {
      const interval = (expiresIn - this.refreshBuffer) * 1000;
      if (interval <= 0) {
        console.log(
          `Warning: Invalid Refresh Interval of ${interval} computed for token that expires in ${expiresIn}`
        );
        return 15 * 60 * 1000; //use default of 15 minutes
      }
      return interval;
    }
  }

  clearTokens() {
    this.accessToken = null;
    this.identityToken = null;
    this.refreshToken = null;
  }

  parseTokens(keycloakResp) {
    // Get our tokens from the response.
    const tokens = {
      ...{
        access_token: null,
        id_token: null,
        refresh_token: null,
        expires_in: 0,
        refresh_expires_in: 0,
      },
      ...keycloakResp,
    };

    this.accessToken = tokens.access_token;
    this.identityToken = tokens.id_token;
    this.refreshToken = tokens.refresh_token;

    // If the session is within our warning threshold pop the warning
    if (tokens.refresh_expires_in <= this.sessionEndWarning) {
      if (typeof this.onSessionEnding === "function")
        this.onSessionEnding(tokens.refresh_expires_in);
    }

    // Set the refresh timeout based on when the token expires
    if (this.sessionTimeout) clearTimeout(this.sessionTimeout);
    this.sessionTimeout = setTimeout(() => {
      this.refresh();
    }, this._getRefreshInterval(tokens.expires_in));

    // Trigger the success callback, provide access token and raw keycloak response to callback
    if (typeof this.onAuthenticate === "function")
      this.onAuthenticate(this.accessToken, keycloakResp);
  }

  fetch(url, data, onSuccess, onError = this.onError) {
    let self = this;
    let xhr = new XMLHttpRequest();
    xhr.open("POST", url);
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    xhr.onload = function () {
      let resp = {};
      try {
        resp = JSON.parse(xhr.responseText);
      } catch (err) {
        return onError(`Error parsing keycloak response ${err}`);
      }

      if (xhr.status !== 200) {
        self.clearTokens();
        onError(resp);
      } else {
        onSuccess(resp);
      }
    };
    xhr.onerror = function () {
      if (xhr.responseText) {
        try {
          onError(JSON.parse(xhr.responseText));
        } catch (err) {
          onError({ error: "Error parsing response from keycloak" });
        }
      } else {
        onError({
          error: "Unable to fetch the token due to a Network Error",
        });
      }
    };
    xhr.ontimeout = function () {
      if (xhr.responseText) {
        try {
          onError(JSON.parse(xhr.responseText));
        } catch (err) {
          onError({ error: "Error parsing response from keycloak" });
        }
      } else {
        onError({
          error: "Unable to fetch the token due to a Network Timeout Error",
        });
      }
    };
    xhr.send(urlencodeFormData(data));
  }

  codeFlowAuth(transaction) {
    const url = `${this.browserFlowUrl}/realms/${transaction?.realm || this.realm}/protocol/openid-connect/token`;
    const data = new FormData();
    data.append("code", this.code);
    data.append("grant_type", "authorization_code");
    data.append("client_id", this.client);
    data.append("redirect_uri", transaction?.redirectUrl || this.redirectUrl);
    if (transaction?.verifier) data.append("code_verifier", transaction.verifier);
    this.fetch(url, data, this.parseTokens.bind(this));
  }

  refresh() {
    const url = `${this.refreshUrl}/realms/${this.realm}/protocol/openid-connect/token`;
    const data = new FormData();
    data.append("refresh_token", this.refreshToken);
    data.append("grant_type", "refresh_token");
    data.append("client_id", this.client);
    this.fetch(url, data, this.parseTokens.bind(this));
  }

  directGrantAuthenticate(user, pass) {
    const url = `${this.directGrantUrl}/realms/${this.realm}/protocol/openid-connect/token`;
    const data = new FormData();
    data.append("grant_type", "password");
    data.append("client_id", this.client);
    data.append("scope", this.scope);
    data.append("username", user);
    data.append("password", pass);
    this.fetch(url, data, this.parseTokens.bind(this));
  }

  directGrantX509Authenticate(overrides = {}) {
    const realm = overrides.realm || this.realm;
    const scope = overrides.scope || this.scope;
    const url = `${this.directGrantUrl}/realms/${realm}/protocol/openid-connect/token`;
    const data = new FormData();
    data.append("grant_type", "password");
    data.append("client_id", this.client);
    data.append("scope", scope);
    data.append("username", "");
    data.append("password", "");
    this.fetch(url, data, this.parseTokens.bind(this));
  }

  getAccessToken() {
    return this.accessToken;
  }

  getIdentityToken() {
    return this.identityToken;
  }

  logout({ redirect = true } = {}) {
    if (!this.logoutUrl) {
      console.log("Configure a logout URL to enable Keycloak Logout flow");
      return;
    }

    const base = `${this.logoutUrl}/realms/${this.realm}/protocol/openid-connect/logout`;
    const params = new URLSearchParams();

    if (this.identityToken) params.append("id_token_hint", this.identityToken);
    if (this.client) params.append("client_id", this.client);

    if (redirect && this.redirectUrl) {
      params.append("post_logout_redirect_uri", this.redirectUrl);
      window.location.href = `${base}?${params}`;
    } else {
      if (this.refreshToken) params.append("refresh_token", this.refreshToken);
      this.clearTokens();
      this.fetch(base, params, () => {
        if (typeof this.onLogout === "function") this.onLogout();
      });
    }
  }
}

const tokenToObject = function (token) {
  try {
    const base64Url = token.split(".")[1];
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split("")
        .map(function (c) {
          return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
        })
        .join("")
    );
    return JSON.parse(jsonPayload);
  } catch (err) {
    console.log("Error parsing token: ", err);
    return null;
  }
};

export { Keycloak as default, tokenToObject };
