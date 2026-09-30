import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { test } from 'node:test';
import Keycloak from '../Keycloak.js';

function fixture(t, options = {}) {
  const data = new Map();
  const requests = [];
  const errors = [];
  const appUrl = 'https://cumulus.dev.cwbi.us/products?unit=mm#map';
  const browser = {
    crypto: webcrypto,
    location: new URL(appUrl),
    sessionStorage: {
      getItem: (key) => data.get(key) ?? null,
      setItem: (key, value) => data.set(key, value),
      removeItem: (key) => data.delete(key),
    },
    history: {
      replaceState: (_state, _title, path) => {
        browser.location = new URL(path, browser.location.origin);
      },
    },
  };
  const previousWindow = globalThis.window;
  const previousXhr = globalThis.XMLHttpRequest;
  globalThis.window = browser;
  globalThis.XMLHttpRequest = class {
    open(method, url) { this.method = method; this.url = url; }
    setRequestHeader() {}
    send(form) { requests.push({ method: this.method, url: this.url, form }); }
  };
  t.after(() => {
    globalThis.window = previousWindow;
    globalThis.XMLHttpRequest = previousXhr;
  });
  const client = new Keycloak({
    browserFlowUrl: 'https://identity-test.cwbi.mil/auth',
    keycloakUrl: 'https://identity-test.cwbi.mil/auth',
    realm: 'cwbi',
    client: 'cumulus',
    redirectUrl: 'https://cumulus.dev.cwbi.us',
    onError: (error) => errors.push(error),
    ...options,
  });
  return { browser, client, data, requests, errors, appUrl };
}

test('browser login sends PKCE S256 and exchanges a code using the saved verifier', async (t) => {
  const f = fixture(t);
  const navigation = f.client.authenticate({ kc_idp_hint: 'federation-eams' });
  assert.equal(f.browser.location.href, f.appUrl);
  await navigation;
  const authorize = new URL(f.browser.location.href);
  assert.equal(authorize.pathname, '/auth/realms/cwbi/protocol/openid-connect/auth');
  assert.equal(authorize.searchParams.get('kc_idp_hint'), 'federation-eams');
  assert.equal(authorize.searchParams.get('response_type'), 'code');
  assert.equal(authorize.searchParams.get('code_challenge_method'), 'S256');
  const state = authorize.searchParams.get('state');
  assert.ok(state);
  const saved = JSON.parse(f.data.get(`usace-keycloak:pkce:${state}`));
  assert.equal(
    createHash('sha256').update(saved.verifier).digest('base64url'),
    authorize.searchParams.get('code_challenge')
  );
  f.browser.location = new URL(`https://cumulus.dev.cwbi.us/?code=sample-code&state=${state}`);
  f.client.checkForSession();
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].url, 'https://identity-test.cwbi.mil/auth/realms/cwbi/protocol/openid-connect/token');
  assert.equal(f.requests[0].form.get('grant_type'), 'authorization_code');
  assert.equal(f.requests[0].form.get('code'), 'sample-code');
  assert.equal(f.requests[0].form.get('code_verifier'), saved.verifier);
  assert.equal(f.requests[0].form.get('redirect_uri'), 'https://cumulus.dev.cwbi.us');
  assert.equal(f.data.has(`usace-keycloak:pkce:${state}`), false);
  assert.equal(f.browser.location.search, '');
  assert.equal(f.errors.length, 0);
});

test('unknown, missing, and reused state never exchange a code', async (t) => {
  const f = fixture(t);
  await f.client.authenticate();
  const validState = new URL(f.browser.location.href).searchParams.get('state');
  for (const state of ['', 'unknown-state']) {
    f.browser.location = new URL(`https://cumulus.dev.cwbi.us/?code=sample-code${state ? `&state=${state}` : ''}`);
    f.client.checkForSession();
  }
  assert.equal(f.requests.length, 0);
  assert.equal(f.errors.length, 2);
  f.browser.location = new URL(`https://cumulus.dev.cwbi.us/?code=sample-code&state=${validState}`);
  f.client.checkForSession();
  f.browser.location = new URL(`https://cumulus.dev.cwbi.us/?code=sample-code&state=${validState}`);
  f.client.checkForSession();
  assert.equal(f.requests.length, 1);
  assert.equal(f.errors.length, 3);
});

test('expired state and provider error are rejected and callback parameters are cleared', async (t) => {
  const f = fixture(t);
  await f.client.authenticate();
  const state = new URL(f.browser.location.href).searchParams.get('state');
  const key = `usace-keycloak:pkce:${state}`;
  f.data.set(key, JSON.stringify({ ...JSON.parse(f.data.get(key)), createdAt: Date.now() - 16 * 60 * 1000 }));
  f.browser.location = new URL(`https://cumulus.dev.cwbi.us/?code=sample-code&state=${state}&unit=mm`);
  f.client.checkForSession();
  assert.equal(f.requests.length, 0);
  assert.equal(f.browser.location.search, '?unit=mm');
  assert.match(f.errors.at(-1).message, /expired/);

  await f.client.authenticate();
  const nextState = new URL(f.browser.location.href).searchParams.get('state');
  f.browser.location = new URL(`https://cumulus.dev.cwbi.us/?error=access_denied&state=${nextState}`);
  f.client.checkForSession();
  assert.equal(f.requests.length, 0);
  assert.match(f.errors.at(-1).message, /access_denied/);
  assert.equal(f.browser.location.search, '');
});

test('realm and redirect overrides survive the callback', async (t) => {
  const f = fixture(t);
  await f.client.authenticate({ realm: 'alternate', redirectUrl: 'https://cumulus.dev.cwbi.us/callback' });
  const authorize = new URL(f.browser.location.href);
  const state = authorize.searchParams.get('state');
  assert.equal(authorize.pathname, '/auth/realms/alternate/protocol/openid-connect/auth');
  f.browser.location = new URL(`https://cumulus.dev.cwbi.us/callback?code=sample-code&state=${state}`);
  f.client.checkForSession();
  assert.equal(f.requests[0].url, 'https://identity-test.cwbi.mil/auth/realms/alternate/protocol/openid-connect/token');
  assert.equal(f.requests[0].form.get('redirect_uri'), 'https://cumulus.dev.cwbi.us/callback');
});

test('direct grant and refresh remain unchanged; PKCE can be disabled for legacy clients', async (t) => {
  const f = fixture(t, { pkceMethod: false, refreshToken: 'old-refresh' });
  await f.client.authenticate();
  const authorize = new URL(f.browser.location.href);
  assert.equal(authorize.searchParams.has('code_challenge'), false);
  f.browser.location = new URL('https://cumulus.dev.cwbi.us/?code=sample-code&session_state=session');
  f.client.checkForSession();
  assert.equal(f.requests[0].form.has('code_verifier'), false);
  f.client.directGrantAuthenticate('user', 'password');
  assert.equal(f.requests[1].form.get('grant_type'), 'password');
  f.client.refresh();
  assert.equal(f.requests[2].form.get('grant_type'), 'refresh_token');
  assert.equal(f.requests[2].form.get('refresh_token'), 'old-refresh');
});

test('browser login fails closed when Web Crypto is unavailable', async (t) => {
  const f = fixture(t);
  f.browser.crypto = undefined;
  await f.client.authenticate();
  assert.equal(f.browser.location.href, f.appUrl);
  assert.equal(f.data.size, 0);
  assert.match(f.errors[0].message, /Web Crypto/);
});
