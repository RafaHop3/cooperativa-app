/**
 * Authentication module for cooperativa-app
 * Handles token management and security
 */

// Security configuration
const API_BASE_URL = window.API_URL || 'http://127.0.0.1:8000';
const TOKEN_ENDPOINT = '/token';
const TOKEN_STORAGE_KEY = 'cooperativa_auth_token';

// Log API URL being used (for debugging)
console.log('Using API URL:', API_BASE_URL);

/**
 * DOMPurify configuration - will be loaded from CDN
 * This ensures all displayed content is properly sanitized
 */
document.addEventListener('DOMContentLoaded', () => {
  // Add DOMPurify script if it's not already loaded
  if (typeof DOMPurify === 'undefined') {
    const script = document.createElement('script');
    script.src = 'https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.6/purify.min.js';
    script.integrity = 'sha512-H+rglffZ6f5gF7UJgvH4Naa+fGCgjrHKMgoFOGmcPTRwR6mL6VYxOXkomaxHIKFVafPV7CiLwxRFDMEqLaESQ==';
    script.crossOrigin = 'anonymous';
    script.referrerPolicy = 'no-referrer';
    document.head.appendChild(script);
  }
});

/**
 * Sanitize any string to prevent XSS attacks
 * @param {string} content - Content to sanitize
 * @returns {string} - Sanitized content
 */
function sanitizeContent(content) {
  if (!content) return '';
  
  // Use DOMPurify if available
  if (typeof DOMPurify !== 'undefined') {
    return DOMPurify.sanitize(content);
  }
  
  // Fallback basic sanitization
  return String(content)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Login function to authenticate user and store token
 * @param {string} username - Username
 * @param {string} password - Password
 * @returns {Promise<boolean>} - Success status
 */
async function login(username, password) {
  try {
    const formData = new URLSearchParams();
    formData.append('username', username);
    formData.append('password', password);

    const response = await fetch(`${API_BASE_URL}${TOKEN_ENDPOINT}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: formData
    });

    if (!response.ok) {
      console.error('Login failed:', response.status);
      return false;
    }

    const data = await response.json();
    
    // Store the token in localStorage with expiry
    const tokenData = {
      token: data.access_token,
      type: data.token_type,
      expires: Date.now() + (30 * 60 * 1000) // 30 minutes expiry
    };
    
    localStorage.setItem(TOKEN_STORAGE_KEY, JSON.stringify(tokenData));
    return true;
  } catch (error) {
    console.error('Login error:', error);
    return false;
  }
}

/**
 * Check if user is authenticated with a valid token
 * @returns {boolean} - Authentication status
 */
function isAuthenticated() {
  try {
    const tokenData = JSON.parse(localStorage.getItem(TOKEN_STORAGE_KEY) || '{}');
    
    // Check if token exists and is not expired
    if (!tokenData.token || !tokenData.expires) {
      return false;
    }
    
    return Date.now() < tokenData.expires;
  } catch (error) {
    console.error('Token validation error:', error);
    return false;
  }
}

/**
 * Get the authentication token for API requests
 * @returns {string|null} - The authentication token or null if not authenticated
 */
function getAuthToken() {
  try {
    if (!isAuthenticated()) {
      return null;
    }
    
    const tokenData = JSON.parse(localStorage.getItem(TOKEN_STORAGE_KEY));
    return tokenData.token;
  } catch (error) {
    console.error('Error getting auth token:', error);
    return null;
  }
}

/**
 * Logout user by removing the token
 */
function logout() {
  localStorage.removeItem(TOKEN_STORAGE_KEY);
  // Redirect to login page
  window.location.href = 'login.html';
}

/**
 * Make an authenticated API request
 * @param {string} endpoint - API endpoint (without base URL)
 * @param {Object} options - Fetch options
 * @returns {Promise<Object>} - API response
 */
async function authenticatedFetch(endpoint, options = {}) {
  const token = getAuthToken();
  
  if (!token) {
    // Redirect to login if not authenticated
    window.location.href = 'login.html';
    return null;
  }
  
  const url = `${API_BASE_URL}${endpoint}`;
  
  // Add authorization header
  const headers = {
    ...options.headers,
    'Authorization': `Bearer ${token}`
  };
  
  try {
    const response = await fetch(url, {
      ...options,
      headers
    });
    
    // Handle 401 Unauthorized (expired token)
    if (response.status === 401) {
      logout();
      return null;
    }
    
    return response;
  } catch (error) {
    console.error(`API request error for ${endpoint}:`, error);
    throw error;
  }
}
