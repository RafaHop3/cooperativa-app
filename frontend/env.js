/**
 * Environment Configuration for Cooperativa App
 * This file handles environment-specific configuration like API URLs
 */

(function() {
    // Get environment from window if available (set by Render)
    window.ENV = window.ENV || {};
    
    // API URL - this will be set by Render in production via the API_URL env var
    window.ENV.API_URL = window.ENV.API_URL || 'http://127.0.0.1:8000';
    
    // Other environment variables can be added here
    window.ENV.APP_VERSION = '1.0.0';
    window.ENV.APP_ENV = window.ENV.APP_ENV || 'development';
    
    // Function to get environment variables
    window.getEnv = function(key, defaultValue) {
        return window.ENV[key] || defaultValue;
    };
    
    console.log('Environment loaded:', {
        API_URL: window.ENV.API_URL,
        APP_ENV: window.ENV.APP_ENV
    });
})();
