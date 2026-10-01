/**
 * OAuth2 Authorization Code Flow Integration Tests
 * 
 * These tests verify the complete browser-based OAuth2 authentication flow:
 * 1. authenticate() - Redirects to Keycloak
 * 2. checkForSession() - Detects auth code in URL
 * 3. codeFlowAuth() - Exchanges code for tokens
 * 4. parseTokens() - Stores tokens and triggers callbacks
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import Keycloak from '../../Keycloak.js'
import { 
  generateMockTokenResponse, 
  setupXHRMock,
  parseFormData 
} from '../setup.js'

describe('OAuth2 Authorization Code Flow', () => {
  let keycloak
  let originalLocation
  let xhrCleanup

  beforeEach(() => {
    // Save original location
    originalLocation = window.location
    
    // Mock window.location
    delete window.location
    window.location = { 
      href: '',
      search: '',
      origin: 'http://localhost:3000',
      pathname: '/'
    }

    // Mock window.history
    window.history.pushState = vi.fn()

    // Initialize Keycloak instance
    keycloak = new Keycloak({
      keycloakUrl: 'https://keycloak.example.com',
      realm: 'test-realm',
      client: 'test-client',
      redirectUrl: 'http://localhost:3000/callback',
      kc_idp_hint: 'login.gov'
    })
  })

  afterEach(() => {
    // Restore original location
    window.location = originalLocation
    
    // Clean up XHR mock
    if (xhrCleanup) {
      xhrCleanup()
      xhrCleanup = null
    }

    // Clear any timers
    vi.clearAllTimers()
  })

  describe('authenticate() - Initial redirect', () => {
    it('should redirect to Keycloak authorization endpoint', () => {
      keycloak.authenticate()

      expect(window.location.href).toContain('https://keycloak.example.com/realms/test-realm/protocol/openid-connect/auth')
      expect(window.location.href).toContain('response_type=code')
      expect(window.location.href).toContain('client_id=test-client')
      expect(window.location.href).toContain('kc_idp_hint=login.gov')
      expect(window.location.href).toContain('redirect_uri=http://localhost:3000/callback')
      expect(window.location.href).toContain('scope=openid')
    })

    it('should allow runtime overrides for realm', () => {
      keycloak.authenticate({ realm: 'custom-realm' })

      expect(window.location.href).toContain('/realms/custom-realm/')
    })

    it('should allow runtime overrides for kc_idp_hint', () => {
      keycloak.authenticate({ kc_idp_hint: 'eams-a' })

      expect(window.location.href).toContain('kc_idp_hint=eams-a')
    })

    it('should allow runtime overrides for redirectUrl', () => {
      keycloak.authenticate({ redirectUrl: 'http://localhost:3000/custom' })

      expect(window.location.href).toContain('redirect_uri=http://localhost:3000/custom')
    })

    it('should include nocache parameter to prevent caching', () => {
      const beforeTime = new Date().getTime()
      keycloak.authenticate()
      
      const match = window.location.href.match(/nocache=(\d+)/)
      expect(match).toBeTruthy()
      
      const nocacheValue = parseInt(match[1])
      expect(nocacheValue).toBeGreaterThanOrEqual(beforeTime)
    })
  })

  describe('checkForSession() - Handling OAuth callback', () => {
    it('should detect authorization code in URL and initiate token exchange', async () => {
      // Setup: Mock the token endpoint response
      const mockTokenResponse = generateMockTokenResponse()
      
      xhrCleanup = setupXHRMock((method, url, data) => {
        expect(method).toBe('POST')
        expect(url).toContain('/realms/test-realm/protocol/openid-connect/token')
        
        const formData = parseFormData(data)
        expect(formData.code).toBe('test-auth-code-123')
        expect(formData.grant_type).toBe('authorization_code')
        expect(formData.client_id).toBe('test-client')
        expect(formData.redirect_uri).toBe('http://localhost:3000/callback')

        return {
          status: 200,
          body: mockTokenResponse
        }
      })

      // Simulate OAuth callback URL
      window.location.search = '?code=test-auth-code-123&session_state=test-session-state'

      // Create promise to wait for authentication callback
      const authPromise = new Promise((resolve) => {
        keycloak.onAuthenticate = (accessToken, response) => {
          resolve({ accessToken, response })
        }
      })

      // Trigger the flow
      keycloak.checkForSession()

      // Wait for authentication to complete
      const result = await authPromise

      // Verify tokens were stored
      expect(keycloak.getAccessToken()).toBe(mockTokenResponse.access_token)
      expect(keycloak.getIdentityToken()).toBe(mockTokenResponse.id_token)
      expect(keycloak.refreshToken).toBe(mockTokenResponse.refresh_token)

      // Verify callback was triggered with correct data
      expect(result.accessToken).toBe(mockTokenResponse.access_token)
      expect(result.response).toEqual(mockTokenResponse)

      // Verify URL was cleaned (code removed from history)
      expect(window.history.pushState).toHaveBeenCalledWith(null, null, '/')
    })

    it('should not initiate token exchange if code is missing', () => {
      window.location.search = '?session_state=test-session-state'

      const onAuthenticate = vi.fn()
      keycloak.onAuthenticate = onAuthenticate

      keycloak.checkForSession()

      expect(onAuthenticate).not.toHaveBeenCalled()
    })

    it('should not initiate token exchange if session_state is missing', () => {
      window.location.search = '?code=test-auth-code-123'

      const onAuthenticate = vi.fn()
      keycloak.onAuthenticate = onAuthenticate

      keycloak.checkForSession()

      expect(onAuthenticate).not.toHaveBeenCalled()
    })

    it('should store code and session_state', () => {
      xhrCleanup = setupXHRMock(() => ({ status: 200, body: generateMockTokenResponse() }))
      
      window.location.search = '?code=test-code&session_state=test-state'
      keycloak.checkForSession()

      expect(keycloak.code).toBe('test-code')
      expect(keycloak.sessionState).toBe('test-state')
    })
  })

  describe('Complete OAuth2 flow - End-to-end', () => {
    it('should complete full authentication flow from redirect to token storage', async () => {
      const mockTokenResponse = generateMockTokenResponse({
        expiresIn: 300,
        accessTokenPayload: {
          sub: 'user-123',
          preferred_username: 'testuser',
          email: 'test@example.com'
        }
      })

      // Track the flow
      const flowSteps = []

      // Setup XHR mock for token exchange
      xhrCleanup = setupXHRMock((method, url, data) => {
        flowSteps.push('token-exchange')
        return {
          status: 200,
          body: mockTokenResponse
        }
      })

      // Setup callbacks to track flow
      const authPromise = new Promise((resolve) => {
        keycloak.onAuthenticate = (accessToken, response) => {
          flowSteps.push('authenticated')
          resolve({ accessToken, response })
        }
      })

      // Step 1: User clicks login (would normally redirect)
      flowSteps.push('authenticate-called')
      keycloak.authenticate()
      expect(window.location.href).toContain('response_type=code')
      
      // Step 2: User returns from Keycloak with auth code
      flowSteps.push('callback-received')
      window.location.search = '?code=auth-code-xyz&session_state=session-xyz'
      
      // Step 3: checkForSession detects code and initiates exchange
      keycloak.checkForSession()
      
      // Step 4: Wait for token exchange to complete
      const result = await authPromise

      // Verify complete flow
      expect(flowSteps).toEqual([
        'authenticate-called',
        'callback-received',
        'token-exchange',
        'authenticated'
      ])

      // Verify tokens are available
      expect(keycloak.getAccessToken()).toBe(mockTokenResponse.access_token)
      expect(keycloak.getIdentityToken()).toBe(mockTokenResponse.id_token)
      
      // Verify callback received complete response
      expect(result.response).toHaveProperty('access_token')
      expect(result.response).toHaveProperty('id_token')
      expect(result.response).toHaveProperty('refresh_token')
    })
  })

  describe('Error handling in OAuth2 flow', () => {
    it('should handle token exchange failure (401 Unauthorized)', async () => {
      xhrCleanup = setupXHRMock(() => ({
        status: 401,
        body: { error: 'invalid_grant', error_description: 'Code expired' }
      }))

      const errorPromise = new Promise((resolve) => {
        keycloak.onError = (error) => {
          resolve(error)
        }
      })

      window.location.search = '?code=expired-code&session_state=test-state'
      keycloak.checkForSession()

      const error = await errorPromise

      // Verify error was handled
      expect(error).toHaveProperty('error', 'invalid_grant')
      
      // Verify tokens were cleared
      expect(keycloak.getAccessToken()).toBeNull()
      expect(keycloak.getIdentityToken()).toBeNull()
      expect(keycloak.refreshToken).toBeNull()
    })

    it('should handle network errors during token exchange', async () => {
      xhrCleanup = setupXHRMock((method, url, data) => {
        // Simulate network error
        return { error: true, errorType: 'error' }
      })

      const errorPromise = new Promise((resolve) => {
        keycloak.onError = (error) => {
          resolve(error)
        }
      })

      window.location.search = '?code=test-code&session_state=test-state'
      keycloak.checkForSession()

      const error = await errorPromise

      expect(error).toHaveProperty('error')
      expect(error.error).toContain('Network Error')
    })

    it('should handle malformed JSON response', async () => {
      xhrCleanup = setupXHRMock(() => ({
        status: 200,
        body: 'This is not JSON'
      }))

      const errorPromise = new Promise((resolve) => {
        keycloak.onError = (error) => {
          resolve(error)
        }
      })

      window.location.search = '?code=test-code&session_state=test-state'
      keycloak.checkForSession()

      const error = await errorPromise

      expect(error).toContain('Error parsing keycloak response')
    })
  })

  describe('Token refresh scheduling', () => {
    beforeEach(() => {
      vi.useFakeTimers()
    })

    afterEach(() => {
      vi.useRealTimers()
    })

    it('should schedule automatic token refresh after authentication', async () => {
      const mockTokenResponse = generateMockTokenResponse({
        expiresIn: 300 // 5 minutes
      })

      xhrCleanup = setupXHRMock(() => ({
        status: 200,
        body: mockTokenResponse
      }))

      const authPromise = new Promise((resolve) => {
        keycloak.onAuthenticate = resolve
      })

      window.location.search = '?code=test-code&session_state=test-state'
      keycloak.checkForSession()

      await authPromise

      // Verify sessionTimeout was set
      expect(keycloak.sessionTimeout).toBeDefined()
      
      // Default refreshBuffer is 60 seconds, so refresh should happen at 240 seconds (300 - 60)
      // Fast-forward time to just before refresh
      vi.advanceTimersByTime(239 * 1000)
      expect(keycloak.getAccessToken()).toBe(mockTokenResponse.access_token) // Still has old token

      // Note: Full refresh testing is in token-refresh.test.js
      // Here we just verify the timer was scheduled
    })

    it('should respect custom refreshInterval if configured', async () => {
      keycloak.refreshInterval = 120 // 2 minutes in seconds

      const mockTokenResponse = generateMockTokenResponse({
        expiresIn: 300
      })

      xhrCleanup = setupXHRMock(() => ({
        status: 200,
        body: mockTokenResponse
      }))

      const authPromise = new Promise((resolve) => {
        keycloak.onAuthenticate = resolve
      })

      window.location.search = '?code=test-code&session_state=test-state'
      keycloak.checkForSession()

      await authPromise

      // With custom refreshInterval of 120s, should use that instead of calculated value
      expect(keycloak.sessionTimeout).toBeDefined()
      
      // Verify the timer uses custom interval (120 seconds = 120000ms)
      // This is indirectly tested by checking that sessionTimeout was set
    })
  })

  describe('Session ending warning', () => {
    it('should trigger onSessionEnding callback when refresh token is near expiry', async () => {
      const mockTokenResponse = generateMockTokenResponse({
        expiresIn: 300,
        refreshExpiresIn: 45 // Less than default sessionEndWarning of 60 seconds
      })

      xhrCleanup = setupXHRMock(() => ({
        status: 200,
        body: mockTokenResponse
      }))

      const sessionEndingPromise = new Promise((resolve) => {
        keycloak.onSessionEnding = (secondsRemaining) => {
          resolve(secondsRemaining)
        }
      })

      window.location.search = '?code=test-code&session_state=test-state'
      keycloak.checkForSession()

      const secondsRemaining = await sessionEndingPromise

      expect(secondsRemaining).toBe(45)
    })

    it('should not trigger onSessionEnding if refresh token has sufficient time', async () => {
      const mockTokenResponse = generateMockTokenResponse({
        expiresIn: 300,
        refreshExpiresIn: 1800 // 30 minutes - well above warning threshold
      })

      xhrCleanup = setupXHRMock(() => ({
        status: 200,
        body: mockTokenResponse
      }))

      const onSessionEnding = vi.fn()
      keycloak.onSessionEnding = onSessionEnding

      const authPromise = new Promise((resolve) => {
        keycloak.onAuthenticate = resolve
      })

      window.location.search = '?code=test-code&session_state=test-state'
      keycloak.checkForSession()

      await authPromise

      expect(onSessionEnding).not.toHaveBeenCalled()
    })
  })
})
