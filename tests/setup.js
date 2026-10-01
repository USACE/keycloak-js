/**
 * Test Setup and Utilities
 * 
 * This file provides mock generators and test utilities for Keycloak testing.
 */

/**
 * Generate a mock JWT token
 * @param {Object} payload - Token payload
 * @param {Object} header - Token header (optional)
 * @returns {string} Mock JWT token
 */
export function generateMockToken(payload = {}, header = { alg: 'RS256', typ: 'JWT' }) {
  const defaultPayload = {
    sub: 'test-user-123',
    name: 'Test User',
    email: 'test@example.com',
    preferred_username: 'testuser',
    exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
    iat: Math.floor(Date.now() / 1000),
    ...payload
  }

  const base64UrlEncode = (obj) => {
    // Convert to JSON string
    const jsonString = JSON.stringify(obj)
    
    // Handle UTF-8 encoding for btoa (which only handles ASCII)
    // This matches what tokenToObject expects to decode
    const utf8Bytes = encodeURIComponent(jsonString).replace(/%([0-9A-F]{2})/g, (match, p1) => {
      return String.fromCharCode(parseInt(p1, 16))
    })
    
    return btoa(utf8Bytes)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '')
  }

  const headerEncoded = base64UrlEncode(header)
  const payloadEncoded = base64UrlEncode(defaultPayload)
  const signature = 'mock-signature'

  return `${headerEncoded}.${payloadEncoded}.${signature}`
}

/**
 * Generate a mock Keycloak token response
 * @param {Object} options - Options for token generation
 * @returns {Object} Mock token response
 */
export function generateMockTokenResponse(options = {}) {
  const {
    expiresIn = 300,
    refreshExpiresIn = 1800,
    includeRefreshToken = true,
    accessTokenPayload = {},
    idTokenPayload = {}
  } = options

  const accessToken = generateMockToken({
    typ: 'Bearer',
    ...accessTokenPayload
  })

  const idToken = generateMockToken({
    typ: 'ID',
    ...idTokenPayload
  })

  const response = {
    access_token: accessToken,
    expires_in: expiresIn,
    refresh_expires_in: refreshExpiresIn,
    token_type: 'Bearer',
    id_token: idToken,
    'not-before-policy': 0,
    scope: 'openid profile email'
  }

  if (includeRefreshToken) {
    response.refresh_token = generateMockToken({
      typ: 'Refresh',
      exp: Math.floor(Date.now() / 1000) + refreshExpiresIn
    })
  }

  return response
}

/**
 * Mock XMLHttpRequest for testing
 * This replaces the global XMLHttpRequest with a controllable mock
 */
export class MockXMLHttpRequest {
  constructor() {
    this.readyState = 0
    this.status = 0
    this.responseText = ''
    this.onreadystatechange = null
    this.onerror = null
    this.onload = null
    this.ontimeout = null
    this._method = null
    this._url = null
    this._requestHeaders = {}
    this._data = null
  }

  open(method, url) {
    this._method = method
    this._url = url
    this.readyState = 1
  }

  setRequestHeader(header, value) {
    this._requestHeaders[header] = value
  }

  send(data) {
    this._data = data
    this.readyState = 2
    
    // Store the request for later inspection/response
    MockXMLHttpRequest.lastRequest = {
      method: this._method,
      url: this._url,
      headers: this._requestHeaders,
      data: this._data,
      xhr: this
    }
  }

  // Helper method to simulate a successful response
  _respond(status, responseText) {
    this.status = status
    this.responseText = typeof responseText === 'string' 
      ? responseText 
      : JSON.stringify(responseText)
    this.readyState = 4
    
    // Trigger onload if it exists (modern approach)
    if (this.onload) {
      this.onload()
    }
    
    // Also trigger onreadystatechange for backwards compatibility
    if (this.onreadystatechange) {
      this.onreadystatechange()
    }
  }

  // Helper method to simulate an error
  _error(errorType = 'error') {
    if (errorType === 'timeout' && this.ontimeout) {
      this.ontimeout()
    } else if (this.onerror) {
      this.onerror()
    }
  }
}

MockXMLHttpRequest.lastRequest = null

/**
 * Setup XMLHttpRequest mock with custom response handler
 * @param {Function} responseHandler - Function that receives (method, url, data) and returns {status, body}
 */
export function setupXHRMock(responseHandler) {
  // Save the original XHR implementation
  const OriginalXHR = (typeof window !== 'undefined' && window.XMLHttpRequest) || global.XMLHttpRequest
  
  const MockXHR = class extends MockXMLHttpRequest {
    send(data) {
      super.send(data)
      
      // Use Promise.resolve().then() to ensure we're on next tick
      // This is more reliable than queueMicrotask in test environments
      Promise.resolve().then(() => {
        try {
          const response = responseHandler(this._method, this._url, this._data)
          if (response.error) {
            this._error(response.errorType || 'error')
          } else {
            this._respond(response.status || 200, response.body)
          }
        } catch (error) {
          console.error('XHR Mock error:', error)
          this._error()
        }
      })
    }
  }
  
  // Replace both global and window XMLHttpRequest
  global.XMLHttpRequest = MockXHR
  if (typeof window !== 'undefined') {
    window.XMLHttpRequest = MockXHR
  }

  // Return cleanup function
  return () => {
    global.XMLHttpRequest = OriginalXHR
    if (typeof window !== 'undefined') {
      window.XMLHttpRequest = OriginalXHR
    }
  }
}

/**
 * Get the parsed data from a form-encoded request
 * @param {string} data - URL-encoded form data
 * @returns {Object} Parsed data object
 */
export function parseFormData(data) {
  const params = new URLSearchParams(data)
  const result = {}
  for (const [key, value] of params.entries()) {
    result[key] = value
  }
  return result
}

/**
 * Setup localStorage mock for testing
 */
export function setupLocalStorage() {
  const storage = {}
  
  global.localStorage = {
    getItem: (key) => storage[key] || null,
    setItem: (key, value) => { storage[key] = String(value) },
    removeItem: (key) => { delete storage[key] },
    clear: () => { Object.keys(storage).forEach(key => delete storage[key]) },
    get length() { return Object.keys(storage).length },
    key: (index) => Object.keys(storage)[index] || null
  }

  return () => {
    Object.keys(storage).forEach(key => delete storage[key])
  }
}

/**
 * Wait for a callback to be called
 * @param {number} timeout - Maximum time to wait in ms
 * @returns {Promise} Promise that resolves when callback is called or rejects on timeout
 */
export function waitForCallback(timeout = 1000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error('Callback timeout'))
    }, timeout)

    return {
      callback: (...args) => {
        clearTimeout(timer)
        resolve(args)
      },
      cancel: () => {
        clearTimeout(timer)
        reject(new Error('Callback cancelled'))
      }
    }
  })
}
