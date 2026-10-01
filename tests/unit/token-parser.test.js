/**
 * tokenToObject Unit Tests
 * 
 * Tests for the JWT token parser utility function.
 * This function decodes JWT tokens and extracts the payload.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { tokenToObject } from '../../Keycloak.js'
import { generateMockToken } from '../setup.js'

describe('tokenToObject', () => {
  let consoleLogSpy

  beforeEach(() => {
    // Spy on console.log to verify error logging
    consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
  })

  afterEach(() => {
    consoleLogSpy.mockRestore()
  })

  describe('Valid token parsing', () => {
    it('should decode a valid JWT token', () => {
      const payload = {
        sub: 'user-123',
        name: 'John Doe',
        email: 'john@example.com',
        exp: 1234567890,
        iat: 1234567800
      }

      const token = generateMockToken(payload)
      const result = tokenToObject(token)

      expect(result).toBeTruthy()
      expect(result.sub).toBe('user-123')
      expect(result.name).toBe('John Doe')
      expect(result.email).toBe('john@example.com')
      expect(result.exp).toBe(1234567890)
      expect(result.iat).toBe(1234567800)
    })

    it('should decode token with minimal payload', () => {
      const payload = { sub: 'minimal-user' }
      const token = generateMockToken(payload)
      const result = tokenToObject(token)

      expect(result).toBeTruthy()
      expect(result.sub).toBe('minimal-user')
    })

    it('should decode token with complex nested objects', () => {
      const payload = {
        sub: 'user-456',
        resource_access: {
          'test-client': {
            roles: ['admin', 'user']
          }
        },
        realm_access: {
          roles: ['offline_access', 'uma_authorization']
        },
        metadata: {
          permissions: ['read', 'write'],
          groups: ['engineering', 'security']
        }
      }

      const token = generateMockToken(payload)
      const result = tokenToObject(token)

      expect(result.sub).toBe('user-456')
      expect(result.resource_access['test-client'].roles).toEqual(['admin', 'user'])
      expect(result.realm_access.roles).toEqual(['offline_access', 'uma_authorization'])
      expect(result.metadata.permissions).toEqual(['read', 'write'])
      expect(result.metadata.groups).toEqual(['engineering', 'security'])
    })

    it('should decode token with special characters in payload', () => {
      const payload = {
        sub: 'user-789',
        name: 'José García',
        email: 'josé@example.com',
        department: 'R&D',
        notes: 'Special chars: ñ, ü, é, ©, ™'
      }

      const token = generateMockToken(payload)
      const result = tokenToObject(token)

      expect(result.name).toBe('José García')
      expect(result.email).toBe('josé@example.com')
      expect(result.department).toBe('R&D')
      expect(result.notes).toContain('ñ')
    })

    it('should decode token with numbers and booleans', () => {
      const payload = {
        sub: 'user-999',
        age: 42,
        active: true,
        verified: false,
        score: 98.6,
        count: 0
      }

      const token = generateMockToken(payload)
      const result = tokenToObject(token)

      expect(result.age).toBe(42)
      expect(result.active).toBe(true)
      expect(result.verified).toBe(false)
      expect(result.score).toBe(98.6)
      expect(result.count).toBe(0)
    })

    it('should decode token with null and empty values', () => {
      const payload = {
        sub: 'user-null',
        middle_name: null,
        nickname: '',
        tags: []
      }

      const token = generateMockToken(payload)
      const result = tokenToObject(token)

      expect(result.middle_name).toBeNull()
      expect(result.nickname).toBe('')
      expect(result.tags).toEqual([])
    })

    it('should handle base64url encoding (with - and _ characters)', () => {
      // JWT tokens use base64url encoding which replaces + with - and / with _
      // The tokenToObject function should handle this correctly
      const payload = {
        sub: 'test-user',
        // Create payload that results in + and / in base64
        data: 'This should create a longer payload that might include characters requiring base64 padding'
      }

      const token = generateMockToken(payload)
      
      // Verify the token contains base64url characters (- or _)
      const parts = token.split('.')
      const hasBase64UrlChars = parts[1].includes('-') || parts[1].includes('_')
      
      const result = tokenToObject(token)

      expect(result).toBeTruthy()
      expect(result.sub).toBe('test-user')
      expect(result.data).toBeTruthy()
    })
  })

  describe('Invalid token handling', () => {
    it('should return null for malformed token (not 3 parts)', () => {
      const result = tokenToObject('invalid.token')

      expect(result).toBeNull()
      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining('Error parsing token'),
        expect.any(Error)
      )
    })

    it('should return null for token with invalid base64', () => {
      const result = tokenToObject('header.!!!invalid-base64!!!.signature')

      expect(result).toBeNull()
      expect(consoleLogSpy).toHaveBeenCalled()
    })

    it('should return null for token with invalid JSON in payload', () => {
      // Create a token with invalid JSON
      const header = btoa(JSON.stringify({ alg: 'RS256' }))
      const invalidPayload = btoa('{ invalid json }')
      const signature = 'signature'
      const token = `${header}.${invalidPayload}.${signature}`

      const result = tokenToObject(token)

      expect(result).toBeNull()
      expect(consoleLogSpy).toHaveBeenCalled()
    })

    it('should return null for empty string', () => {
      const result = tokenToObject('')

      expect(result).toBeNull()
      expect(consoleLogSpy).toHaveBeenCalled()
    })

    it('should return null for null input', () => {
      const result = tokenToObject(null)

      expect(result).toBeNull()
      expect(consoleLogSpy).toHaveBeenCalled()
    })

    it('should return null for undefined input', () => {
      const result = tokenToObject(undefined)

      expect(result).toBeNull()
      expect(consoleLogSpy).toHaveBeenCalled()
    })

    it('should return null for non-string input', () => {
      const result = tokenToObject(12345)

      expect(result).toBeNull()
      expect(consoleLogSpy).toHaveBeenCalled()
    })

    it('should return null for token with only one part', () => {
      const result = tokenToObject('single-part-token')

      expect(result).toBeNull()
      expect(consoleLogSpy).toHaveBeenCalled()
    })

    it('should return null for token with empty parts', () => {
      const result = tokenToObject('..')

      expect(result).toBeNull()
      expect(consoleLogSpy).toHaveBeenCalled()
    })
  })

  describe('Real-world JWT token examples', () => {
    it('should decode a realistic Keycloak access token', () => {
      const payload = {
        exp: 1678901234,
        iat: 1678900934,
        jti: 'c5b1a4e8-3f2d-4a8b-9c7e-1d2f3a4b5c6d',
        iss: 'https://keycloak.example.com/realms/usace',
        aud: 'account',
        sub: 'f1e2d3c4-b5a6-9876-5432-1fedcba09876',
        typ: 'Bearer',
        azp: 'usace-app',
        session_state: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        acr: '1',
        'allowed-origins': ['https://app.example.com'],
        realm_access: {
          roles: ['offline_access', 'uma_authorization', 'default-roles-usace']
        },
        resource_access: {
          'usace-app': {
            roles: ['user', 'admin']
          },
          account: {
            roles: ['manage-account', 'view-profile']
          }
        },
        scope: 'openid profile email',
        sid: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        email_verified: true,
        name: 'John Smith',
        preferred_username: 'john.smith@usace.army.mil',
        given_name: 'John',
        family_name: 'Smith',
        email: 'john.smith@usace.army.mil'
      }

      const token = generateMockToken(payload)
      const result = tokenToObject(token)

      expect(result).toBeTruthy()
      expect(result.sub).toBe('f1e2d3c4-b5a6-9876-5432-1fedcba09876')
      expect(result.preferred_username).toBe('john.smith@usace.army.mil')
      expect(result.email_verified).toBe(true)
      expect(result.realm_access.roles).toContain('offline_access')
      expect(result.resource_access['usace-app'].roles).toContain('admin')
      expect(result['allowed-origins']).toContain('https://app.example.com')
    })

    it('should decode a realistic Keycloak ID token', () => {
      const payload = {
        exp: 1678901234,
        iat: 1678900934,
        auth_time: 1678900934,
        jti: 'd1e2f3a4-b5c6-7890-abcd-ef1234567890',
        iss: 'https://keycloak.example.com/realms/usace',
        aud: 'usace-app',
        sub: 'f1e2d3c4-b5a6-9876-5432-1fedcba09876',
        typ: 'ID',
        azp: 'usace-app',
        nonce: 'n-0S6_WzA2Mj',
        session_state: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        at_hash: 'abc123def456',
        acr: '1',
        sid: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        email_verified: true,
        name: 'Jane Doe',
        preferred_username: 'jane.doe@usace.army.mil',
        given_name: 'Jane',
        family_name: 'Doe',
        email: 'jane.doe@usace.army.mil'
      }

      const token = generateMockToken(payload)
      const result = tokenToObject(token)

      expect(result).toBeTruthy()
      expect(result.typ).toBe('ID')
      expect(result.name).toBe('Jane Doe')
      expect(result.given_name).toBe('Jane')
      expect(result.family_name).toBe('Doe')
      expect(result.at_hash).toBe('abc123def456')
    })
  })

  describe('Edge cases', () => {
    it('should handle token with very long payload', () => {
      const payload = {
        sub: 'user-long',
        // Create a large payload
        data: 'x'.repeat(10000),
        roles: Array(100).fill(0).map((_, i) => `role-${i}`)
      }

      const token = generateMockToken(payload)
      const result = tokenToObject(token)

      expect(result).toBeTruthy()
      expect(result.data.length).toBe(10000)
      expect(result.roles.length).toBe(100)
    })

    it('should extract payload even if signature is invalid', () => {
      // tokenToObject only decodes the payload, doesn't verify signature
      const payload = { sub: 'test-user', name: 'Test' }
      const token = generateMockToken(payload)
      
      // Replace signature with garbage
      const parts = token.split('.')
      const invalidToken = `${parts[0]}.${parts[1]}.INVALID-SIGNATURE-123`

      const result = tokenToObject(invalidToken)

      // Should still decode payload successfully
      expect(result).toBeTruthy()
      expect(result.sub).toBe('test-user')
      expect(result.name).toBe('Test')
    })

    it('should handle token with extra dots', () => {
      const result = tokenToObject('header.payload.signature.extra.dots')

      // Function only looks at parts[1], so might still work or fail
      // depending on the base64 validity
      // This tests the robustness of the implementation
      expect(result).toBeNull()
    })
  })

  describe('Token expiration checking', () => {
    it('should decode expired token (does not validate expiration)', () => {
      const expiredPayload = {
        sub: 'user-expired',
        exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
        iat: Math.floor(Date.now() / 1000) - 7200  // 2 hours ago
      }

      const token = generateMockToken(expiredPayload)
      const result = tokenToObject(token)

      // tokenToObject just decodes, doesn't validate expiration
      expect(result).toBeTruthy()
      expect(result.sub).toBe('user-expired')
      expect(result.exp).toBeLessThan(Math.floor(Date.now() / 1000))
    })

    it('should decode future token', () => {
      const futurePayload = {
        sub: 'user-future',
        exp: Math.floor(Date.now() / 1000) + 7200, // 2 hours from now
        iat: Math.floor(Date.now() / 1000)
      }

      const token = generateMockToken(futurePayload)
      const result = tokenToObject(token)

      expect(result).toBeTruthy()
      expect(result.exp).toBeGreaterThan(Math.floor(Date.now() / 1000))
    })
  })
})
