import { createHash, webcrypto } from 'node:crypto';
import { afterEach, beforeEach, expect, test } from 'vitest';
import Keycloak from '../../Keycloak.js';

let previousWindow;
let previousXhr;

beforeEach(() => {
  previousWindow = globalThis.window;
  previousXhr = globalThis.XMLHttpRequest;
});

afterEach(() => {
  globalThis.window = previousWindow;
  globalThis.XMLHttpRequest = previousXhr;
});

function fixture(options = {}) {
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
  globalThis.window = browser;
  globalThis.XMLHttpRequest = class {
    open(method, url) { this.method = method; this.url = url; }
    setRequestHeader() {}
    send(form) { requests.push({ method: this.method, url: this.url, form }); }
  };
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

test('browser login sends PKCE S256 and exchanges a code using the saved verifier', async () => {
  const f = fixture();
  const navigation = f.client.authenticate({ kc_idp_hint: 'federation-eams' });
  expect(f.browser.location.href).toBe(f.appUrl);
  await navigation;
  const authorize = new URL(f.browser.location.href);
  expect(authorize.pathname).toBe('/auth/realms/cwbi/protocol/openid-connect/auth');
  expect(authorize.searchParams.get('kc_idp_hint')).toBe('federation-eams');
  expect(authorize.searchParams.get('response_type')).toBe('code');
  expect(authorize.searchParams.get('code_challenge_method')).toBe('S256');
  const state = authorize.searchParams.get('state');
  expect(state).toBeTruthy();
  const saved = JSON.parse(f.data.get(`usace-keycloak:pkce:${state}`));
  expect(createHash('sha256').update(saved.verifier).digest('base64url'))
    .toBe(authorize.searchParams.get('code_challenge'));
  f.browser.location = new URL(`https://cumulus.dev.cwbi.us/?code=sample-code&state=${state}`);
  f.client.checkForSession();
  expect(f.requests.length).toBe(1);
  expect(f.requests[0].url).toBe('https://identity-test.cwbi.mil/auth/realms/cwbi/protocol/openid-connect/token');
  expect(f.requests[0].form.get('grant_type')).toBe('authorization_code');
  expect(f.requests[0].form.get('code')).toBe('sample-code');
  expect(f.requests[0].form.get('code_verifier')).toBe(saved.verifier);
  expect(f.requests[0].form.get('redirect_uri')).toBe('https://cumulus.dev.cwbi.us');
  expect(f.data.has(`usace-keycloak:pkce:${state}`)).toBe(false);
  expect(f.browser.location.search).toBe('');
  expect(f.errors.length).toBe(0);
});

test('unknown, missing, and reused state never exchange a code', async () => {
  const f = fixture();
  await f.client.authenticate();
  const validState = new URL(f.browser.location.href).searchParams.get('state');
  for (const state of ['', 'unknown-state']) {
    f.browser.location = new URL(`https://cumulus.dev.cwbi.us/?code=sample-code${state ? `&state=${state}` : ''}`);
    f.client.checkForSession();
  }
  expect(f.requests.length).toBe(0);
  expect(f.errors.length).toBe(2);
  f.browser.location = new URL(`https://cumulus.dev.cwbi.us/?code=sample-code&state=${validState}`);
  f.client.checkForSession();
  f.browser.location = new URL(`https://cumulus.dev.cwbi.us/?code=sample-code&state=${validState}`);
  f.client.checkForSession();
  expect(f.requests.length).toBe(1);
  expect(f.errors.length).toBe(3);
});

test('expired state and provider error are rejected and callback parameters are cleared', async () => {
  const f = fixture();
  await f.client.authenticate();
  const state = new URL(f.browser.location.href).searchParams.get('state');
  const key = `usace-keycloak:pkce:${state}`;
  f.data.set(key, JSON.stringify({ ...JSON.parse(f.data.get(key)), createdAt: Date.now() - 16 * 60 * 1000 }));
  f.browser.location = new URL(`https://cumulus.dev.cwbi.us/?code=sample-code&state=${state}&unit=mm`);
  f.client.checkForSession();
  expect(f.requests.length).toBe(0);
  expect(f.browser.location.search).toBe('?unit=mm');
  expect(f.errors.at(-1).message).toMatch(/expired/);

  await f.client.authenticate();
  const nextState = new URL(f.browser.location.href).searchParams.get('state');
  f.browser.location = new URL(`https://cumulus.dev.cwbi.us/?error=access_denied&state=${nextState}`);
  f.client.checkForSession();
  expect(f.requests.length).toBe(0);
  expect(f.errors.at(-1).message).toMatch(/access_denied/);
  expect(f.browser.location.search).toBe('');
});

test('realm and redirect overrides survive the callback', async () => {
  const f = fixture();
  await f.client.authenticate({ realm: 'alternate', redirectUrl: 'https://cumulus.dev.cwbi.us/callback' });
  const authorize = new URL(f.browser.location.href);
  const state = authorize.searchParams.get('state');
  expect(authorize.pathname).toBe('/auth/realms/alternate/protocol/openid-connect/auth');
  f.browser.location = new URL(`https://cumulus.dev.cwbi.us/callback?code=sample-code&state=${state}`);
  f.client.checkForSession();
  expect(f.requests[0].url).toBe('https://identity-test.cwbi.mil/auth/realms/alternate/protocol/openid-connect/token');
  expect(f.requests[0].form.get('redirect_uri')).toBe('https://cumulus.dev.cwbi.us/callback');
});

test('direct grant and refresh remain unchanged; PKCE can be disabled for legacy clients', async () => {
  const f = fixture({ pkceMethod: false, refreshToken: 'old-refresh' });
  await f.client.authenticate();
  const authorize = new URL(f.browser.location.href);
  expect(authorize.searchParams.has('code_challenge')).toBe(false);
  f.browser.location = new URL('https://cumulus.dev.cwbi.us/?code=sample-code&session_state=session');
  f.client.checkForSession();
  expect(f.requests[0].form.has('code_verifier')).toBe(false);
  f.client.directGrantAuthenticate('user', 'password');
  expect(f.requests[1].form.get('grant_type')).toBe('password');
  f.client.refresh();
  expect(f.requests[2].form.get('grant_type')).toBe('refresh_token');
  expect(f.requests[2].form.get('refresh_token')).toBe('old-refresh');
});

test('browser login fails closed when Web Crypto is unavailable', async () => {
  const f = fixture();
  f.browser.crypto = undefined;
  await f.client.authenticate();
  expect(f.browser.location.href).toBe(f.appUrl);
  expect(f.data.size).toBe(0);
  expect(f.errors[0].message).toMatch(/Web Crypto/);
});
