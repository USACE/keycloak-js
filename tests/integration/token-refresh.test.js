/**
 * Token Refresh Cycle Integration Tests
 * 
 * These tests verify the automatic token refresh functionality:
 * 1. Automatic refresh scheduling based on token expiration
 * 2. Token refresh using refresh_token
 * 3. Re-scheduling refresh after successful refresh
 * 4. Error handling during refresh (expired refresh token, network errors)
 * 5. Manual refresh trigger
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import Keycloak from '../../Keycloak.js'
import { 
  generateMockTokenResponse,
  generateMockToken,
  setupXHRMock,
  parseFormData 
} from '../setup.js'

describe('Token Refresh Cycle', () => {
  let keycloak
  let xhrCleanup

  beforeEach(() => {
    // Use fake timers to control setTimeout
    vi.useFakeTimers()

    // Initialize Keycloak instance
    keycloak = new Keycloak({
      keycloakUrl: 'https://keycloak.example.com',
      realm: 'test-realm',
      client: 'test-client',
      redirectUrl: 'http://localhost:3000/callback'
    })
  })

  afterEach(() => {
    // Clean up XHR mock
    if (xhrCleanup) {
      xhrCleanup()
      xhrCleanup = null
    }

    // Restore real timers
    vi.useRealTimers()
  })

  describe('Automatic refresh scheduling', () => {
    it('should automatically refresh token before it expires', async () => {
      const initialTokenResponse = generateMockTokenResponse({
        expiresIn: 300, // 5 minutes
        refreshExpiresIn: 1800,
        accessTokenPayload: { sub: 'user-123', version: 1 }
      })

      const refreshedTokenResponse = generateMockTokenResponse({
        expiresIn: 300,
        refreshExpiresIn: 1800,
        accessTokenPayload: { sub: 'user-123', version: 2 }
      })

      let requestCount = 0

      xhrCleanup = setupXHRMock((method, url, data) => {
        requestCount++
        
        if (requestCount === 1) {
          // Refresh request
          const formData = parseFormData(data)
          expect(formData.grant_type).toBe('refresh_token')
          expect(formData.refresh_token).toBe(initialTokenResponse.refresh_token)
          expect(formData.client_id).toBe('test-client')
          
          return { status: 200, body: refreshedTokenResponse }
        }
        
        return { status: 200, body: refreshedTokenResponse }
      })

      // Setup to track authentication callbacks
      let authCallCount = 0
      let capturedTokens = []

      keycloak.onAuthenticate = (accessToken) => {
        authCallCount++
        capturedTokens.push(accessToken)
      }

      // Simulate initial authentication (parseTokens, not XHR)
      keycloak.parseTokens(initialTokenResponse)

      // Verify initial token
      expect(keycloak.getAccessToken()).toBe(initialTokenResponse.access_token)
      expect(authCallCount).toBe(1)

      // Calculate when refresh should happen (expires_in - refreshBuffer)
      // Default refreshBuffer is 60 seconds
      // So refresh should happen at 300 - 60 = 240 seconds
      const refreshTime = (300 - 60) * 1000

      // Fast-forward to just before refresh time
      await vi.advanceTimersByTimeAsync(refreshTime - 1000)
      expect(authCallCount).toBe(1) // No refresh yet

      // Fast-forward past refresh time to trigger refresh
      await vi.advanceTimersByTimeAsync(2000)

      // Verify refresh happened
      expect(requestCount).toBe(1) // One refresh request
      expect(authCallCount).toBe(2) // Initial + refresh callback
      expect(keycloak.getAccessToken()).toBe(refreshedTokenResponse.access_token)
      expect(capturedTokens).toHaveLength(2)
    })

    it('should use custom refreshInterval when configured', async () => {
      keycloak.refreshInterval = 120 // 2 minutes in seconds

      const tokenResponse = generateMockTokenResponse({
        expiresIn: 300 // 5 minutes
      })

      const refreshedResponse = generateMockTokenResponse({
        expiresIn: 300
      })

      let requestCount = 0

      xhrCleanup = setupXHRMock((method, url, data) => {
        requestCount++
        return { status: 200, body: refreshedResponse }
      })

      keycloak.parseTokens(tokenResponse)

      // With custom refreshInterval of 120 seconds, should refresh at 120s not 240s
      await vi.advanceTimersByTimeAsync(119 * 1000)
      expect(requestCount).toBe(0)

      await vi.advanceTimersByTimeAsync(2 * 1000)

      expect(requestCount).toBe(1) // Refresh happened
    })

    it('should handle very short token expiration times gracefully', async () => {
      const tokenResponse = generateMockTokenResponse({
        expiresIn: 30 // Only 30 seconds - less than refreshBuffer of 60
      })

      let logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

      xhrCleanup = setupXHRMock(() => ({ status: 200, body: tokenResponse }))

      keycloak.parseTokens(tokenResponse)

      // Should log a warning about invalid refresh interval
      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining('Warning: Invalid Refresh Interval')
      )

      // Should use default of 15 minutes instead
      expect(keycloak.sessionTimeout).toBeDefined()

      logSpy.mockRestore()
    })

    it('should clear previous refresh timeout when scheduling new one', async () => {
      const firstTokenResponse = generateMockTokenResponse({ expiresIn: 300 })
      const secondTokenResponse = generateMockTokenResponse({ expiresIn: 600 })

      xhrCleanup = setupXHRMock(() => ({ status: 200, body: secondTokenResponse }))

      // Set first timeout
      keycloak.parseTokens(firstTokenResponse)
      const firstTimeout = keycloak.sessionTimeout

      // Set second timeout
      keycloak.parseTokens(secondTokenResponse)
      const secondTimeout = keycloak.sessionTimeout

      // Should be different timeout IDs
      expect(firstTimeout).not.toBe(secondTimeout)
      expect(keycloak.sessionTimeout).toBe(secondTimeout)
    })
  })

  describe('Manual token refresh', () => {
    it('should allow manual refresh() call', async () => {
      const tokenResponse = generateMockTokenResponse({
        expiresIn: 300,
        accessTokenPayload: { sub: 'user-123', version: 1 }
      })

      const refreshedResponse = generateMockTokenResponse({
        expiresIn: 300,
        accessTokenPayload: { sub: 'user-123', version: 2 }
      })

      xhrCleanup = setupXHRMock((method, url, data) => {
        // Verify the refresh request
        expect(url).toContain('/realms/test-realm/protocol/openid-connect/token')
        const formData = parseFormData(data)
        expect(formData.grant_type).toBe('refresh_token')
        expect(formData.refresh_token).toBe(tokenResponse.refresh_token)
        expect(formData.client_id).toBe('test-client')
        
        return { status: 200, body: refreshedResponse }
      })

      // Set initial tokens
      keycloak.refreshToken = tokenResponse.refresh_token
      keycloak.accessToken = tokenResponse.access_token

      const authPromise = new Promise((resolve) => {
        keycloak.onAuthenticate = (accessToken, response) => {
          resolve({ accessToken, response })
        }
      })

      // Manually trigger refresh
      keycloak.refresh()

      // Wait for async mock response
      await Promise.resolve()
      const result = await authPromise

      // Verify refresh completed
      expect(result.accessToken).toBe(refreshedResponse.access_token)
      expect(keycloak.getAccessToken()).toBe(refreshedResponse.access_token)
    })

    it('should allow specifying custom refresh URL', async () => {
      keycloak.refreshUrl = 'https://custom-keycloak.example.com'

      const refreshedResponse = generateMockTokenResponse({ expiresIn: 300 })

      xhrCleanup = setupXHRMock((method, url, data) => {
        // Verify custom URL is used
        expect(url).toContain('https://custom-keycloak.example.com')
        expect(url).toContain('/realms/test-realm/protocol/openid-connect/token')
        return { status: 200, body: refreshedResponse }
      })

      keycloak.refreshToken = 'test-refresh-token'

      const authPromise = new Promise((resolve) => {
        keycloak.onAuthenticate = resolve
      })

      keycloak.refresh()

      await Promise.resolve()
      await authPromise
    })
  })

  describe('Refresh error handling', () => {
    it('should handle expired refresh token (401)', async () => {
      const tokenResponse = generateMockTokenResponse({ expiresIn: 300 })

      xhrCleanup = setupXHRMock(() => ({
        status: 401,
        body: { 
          error: 'invalid_grant', 
          error_description: 'Token is not active' 
        }
      }))

      keycloak.refreshToken = tokenResponse.refresh_token
      keycloak.accessToken = tokenResponse.access_token
      keycloak.identityToken = tokenResponse.id_token

      const errorPromise = new Promise((resolve) => {
        keycloak.onError = (error) => {
          resolve(error)
        }
      })

      keycloak.refresh()

      await Promise.resolve()
      const error = await errorPromise

      // Verify error handling
      expect(error).toHaveProperty('error', 'invalid_grant')

      // Verify tokens were cleared
      expect(keycloak.getAccessToken()).toBeNull()
      expect(keycloak.getIdentityToken()).toBeNull()
      expect(keycloak.refreshToken).toBeNull()
    })

    it('should handle network error during refresh', async () => {
      xhrCleanup = setupXHRMock(() => ({
        error: true,
        errorType: 'error'
      }))

      keycloak.refreshToken = 'test-refresh-token'

      const errorPromise = new Promise((resolve) => {
        keycloak.onError = (error) => {
          resolve(error)
        }
      })

      keycloak.refresh()

      await Promise.resolve()
      const error = await errorPromise

      expect(error).toHaveProperty('error')
      expect(error.error).toContain('Network Error')
    })

    it('should handle timeout during refresh', async () => {
      xhrCleanup = setupXHRMock(() => ({
        error: true,
        errorType: 'timeout'
      }))

      keycloak.refreshToken = 'test-refresh-token'

      const errorPromise = new Promise((resolve) => {
        keycloak.onError = (error) => {
          resolve(error)
        }
      })

      keycloak.refresh()

      await Promise.resolve()
      const error = await errorPromise

      expect(error).toHaveProperty('error')
      expect(error.error).toContain('Timeout Error')
    })

    it('should automatically schedule next refresh after successful refresh', async () => {
      const firstResponse = generateMockTokenResponse({
        expiresIn: 300,
        accessTokenPayload: { version: 1 }
      })

      const secondResponse = generateMockTokenResponse({
        expiresIn: 300,
        accessTokenPayload: { version: 2 }
      })

      let refreshCount = 0

      xhrCleanup = setupXHRMock(() => {
        refreshCount++
        return refreshCount === 1
          ? { status: 200, body: firstResponse }
          : { status: 200, body: secondResponse }
      })

      let authCount = 0
      keycloak.onAuthenticate = () => { authCount++ }

      // Initial token setup
      keycloak.refreshToken = 'initial-refresh-token'
      
      // First refresh
      keycloak.refresh()
      await Promise.resolve()

      expect(authCount).toBe(1)
      expect(keycloak.sessionTimeout).toBeDefined()

      // Wait for next auto-refresh (240 seconds = 300 - 60)
      await vi.advanceTimersByTimeAsync(240 * 1000)

      // Second refresh should have happened automatically
      expect(authCount).toBe(2)
      expect(refreshCount).toBe(2)
    })
  })

  describe('Refresh interval calculation', () => {
    it('should calculate refresh interval as 80% of expires_in by default', () => {
      // Test the _getRefreshInterval method directly
      keycloak.refreshBuffer = 60 // Default buffer

      expect(keycloak._getRefreshInterval(300)).toBe(240 * 1000) // (300 - 60) * 1000
      expect(keycloak._getRefreshInterval(600)).toBe(540 * 1000) // (600 - 60) * 1000
      expect(keycloak._getRefreshInterval(3600)).toBe(3540 * 1000) // (3600 - 60) * 1000
    })

    it('should use custom refreshBuffer when configured', () => {
      keycloak.refreshBuffer = 120 // 2 minutes

      expect(keycloak._getRefreshInterval(300)).toBe(180 * 1000) // (300 - 120) * 1000
      expect(keycloak._getRefreshInterval(600)).toBe(480 * 1000) // (600 - 120) * 1000
    })

    it('should use custom refreshInterval when configured, ignoring expires_in', () => {
      keycloak.refreshInterval = 180 // 3 minutes

      expect(keycloak._getRefreshInterval(300)).toBe(180 * 1000)
      expect(keycloak._getRefreshInterval(600)).toBe(180 * 1000)
      expect(keycloak._getRefreshInterval(3600)).toBe(180 * 1000)
    })

    it('should return default 15 minutes when calculated interval is invalid', () => {
      keycloak.refreshBuffer = 400 // More than expires_in

      const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

      const result = keycloak._getRefreshInterval(300) // 300 - 400 = -100 (invalid)

      expect(result).toBe(15 * 60 * 1000) // 15 minutes default
      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining('Warning: Invalid Refresh Interval')
      )

      logSpy.mockRestore()
    })
  })

  describe('Complete refresh cycle', () => {
    it('should perform multiple automatic refreshes over time', async () => {
      const responses = [
        generateMockTokenResponse({ 
          expiresIn: 300,
          accessTokenPayload: { version: 1 }
        }),
        generateMockTokenResponse({ 
          expiresIn: 300,
          accessTokenPayload: { version: 2 }
        }),
        generateMockTokenResponse({ 
          expiresIn: 300,
          accessTokenPayload: { version: 3 }
        })
      ]

      let xhrRequestCount = 0

      xhrCleanup = setupXHRMock(() => {
        // XHR is called for refreshes only (not initial parseTokens)
        const response = responses[xhrRequestCount + 1] // +1 because first response used in parseTokens
        xhrRequestCount++
        return { status: 200, body: response }
      })

      let authCount = 0
      const tokens = []

      keycloak.onAuthenticate = (accessToken) => {
        authCount++
        tokens.push(accessToken)
      }

      // Initial authentication (not via XHR, manually call parseTokens)
      keycloak.parseTokens(responses[0])

      expect(authCount).toBe(1)
      expect(tokens[0]).toBe(responses[0].access_token)

      // First auto-refresh at 240 seconds
      await vi.advanceTimersByTimeAsync(240 * 1000)
      await Promise.resolve() // Let XHR mock resolve

      expect(authCount).toBe(2)
      expect(tokens[1]).toBe(responses[1].access_token)

      // Second auto-refresh at 240 seconds after first refresh
      await vi.advanceTimersByTimeAsync(240 * 1000)
      await Promise.resolve() // Let XHR mock resolve

      // Verify all refreshes happened
      expect(authCount).toBe(3)
      expect(xhrRequestCount).toBe(2) // 2 XHR refresh requests
      expect(tokens).toHaveLength(3)
      expect(tokens[0]).toBe(responses[0].access_token)
      expect(tokens[1]).toBe(responses[1].access_token)
      expect(tokens[2]).toBe(responses[2].access_token)
    })
  })
})
