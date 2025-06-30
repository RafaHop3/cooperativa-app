/**
 * Activity Logger for Cooperativa App
 * Tracks user activities and sends them to the backend
 */

const API_BASE_URL = window.API_URL || 'http://127.0.0.1:8000';
const ACTIVITY_LOG_ENDPOINT = '/api/activity-log';

// Log API URL being used (for debugging)
console.log('ActivityLogger using API URL:', API_BASE_URL);

/**
 * Log a user activity
 * @param {string} activityType - Type of activity (e.g., 'view_page', 'edit_record', etc.)
 * @param {Object} details - Additional details about the activity
 * @returns {Promise<Object>} - Response from the server
 */
async function logActivity(activityType, details = {}) {
    try {
        // Get authentication token
        const authToken = getAuthToken();
        
        if (!authToken) {
            console.warn('Cannot log activity: User not authenticated');
            return null;
        }
        
        // Add timestamp to details
        details.clientTimestamp = new Date().toISOString();
        
        // Create the activity log object
        const activityLog = {
            user_id: '', // Will be set by backend based on token
            activity_type: activityType,
            details: details
        };
        
        // Send the activity to the backend
        const response = await fetch(`${API_BASE_URL}${ACTIVITY_LOG_ENDPOINT}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify(activityLog)
        });
        
        if (!response.ok) {
            throw new Error(`Failed to log activity: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('Error logging activity:', error);
        // Fail silently in production - don't block user interactions due to logging errors
        return null;
    }
}

/**
 * Log page navigation
 * @param {string} pageName - Name of the page being viewed
 */
function logPageView(pageName) {
    logActivity('page_view', { page: pageName });
}

/**
 * Log user interaction with a form
 * @param {string} formId - ID of the form
 * @param {string} action - Action performed (e.g., 'submit', 'reset')
 * @param {Object} formData - Optional data from the form (be careful not to log sensitive data)
 */
function logFormInteraction(formId, action, formData = {}) {
    // Remove sensitive fields like passwords before logging
    const sanitizedData = { ...formData };
    if (sanitizedData.password) sanitizedData.password = '[REDACTED]';
    if (sanitizedData.senha) sanitizedData.senha = '[REDACTED]';
    
    logActivity('form_interaction', {
        form: formId,
        action: action,
        data: sanitizedData
    });
}

/**
 * Log data modification
 * @param {string} dataType - Type of data being modified (e.g., 'cooperativado', 'foto')
 * @param {string} action - Action performed (e.g., 'create', 'update', 'delete')
 * @param {string|number} recordId - ID of the record being modified
 * @param {Object} changes - Changes made to the data (optional)
 */
function logDataModification(dataType, action, recordId, changes = {}) {
    logActivity('data_modification', {
        dataType,
        action,
        recordId,
        changes
    });
}

/**
 * Automatically attach activity logging to common interactions
 */
function initActivityLogging() {
    // Log page views
    logPageView(window.location.pathname);
    
    // Log form submissions
    document.addEventListener('submit', function(event) {
        const form = event.target;
        if (form.id) {
            // Collect non-sensitive form data
            const formData = {};
            new FormData(form).forEach((value, key) => {
                // Don't log password fields
                if (!key.includes('password') && !key.includes('senha')) {
                    formData[key] = value;
                }
            });
            
            logFormInteraction(form.id, 'submit', formData);
        }
    });
    
    // Add logging to navigation events
    const navLinks = document.querySelectorAll('nav a');
    navLinks.forEach(link => {
        link.addEventListener('click', function() {
            logActivity('navigation', { 
                from: window.location.pathname,
                to: this.getAttribute('href')
            });
        });
    });
}

// Export functions for use in other scripts
window.ActivityLogger = {
    logActivity,
    logPageView,
    logFormInteraction,
    logDataModification,
    initActivityLogging
};

// Initialize activity logging when the DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Only initialize if the user is logged in
    if (typeof isAuthenticated === 'function' && isAuthenticated()) {
        initActivityLogging();
    }
});
