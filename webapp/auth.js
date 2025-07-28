/**
 * auth.js
 * Handles user authentication for a session-based (cookie) backend.
 */

// This is the key for the API URL
const API_URL_KEY = 'threatpunch_api_url';

// A simple in-memory flag to track auth state after a successful check.
let isAuthenticated = false;

/**
 * Checks the user's authentication status by pinging a protected endpoint.
 * This is the primary way to determine if the user's session is active.
 * @returns {Promise<boolean>} - True if the session is active, false otherwise.
 */
export async function checkAuthentication() {
    const apiUrl = getApiUrl();
    if (!apiUrl) {
        isAuthenticated = false;
        return false;
    }

    try {
        // IMPORTANT: Your backend needs a protected endpoint like '/api/user'
        // that will succeed if the user has a valid session cookie, and fail otherwise.
        const response = await fetch(`${apiUrl}/api/user`, {
            method: 'GET',
            // Crucial for sending session cookies with the request
            credentials: 'include',
        });

        isAuthenticated = response.ok;
        return isAuthenticated;

    } catch (error) {
        console.error('Auth check failed:', error);
        isAuthenticated = false;
        return false;
    }
}


/**
 * Attempts to log in the user with the provided credentials using form data.
 * @param {string} email - The user's email.
 * @param {string} password - The user's password.
 * @returns {Promise<object>} - A promise that resolves with the result of the login attempt.
 */
export async function login(email, password) {
    const apiUrl = getApiUrl();
    if (!apiUrl) {
        return { success: false, message: 'API URL is not set. Please configure it in the profile.' };
    }

    // The backend expects form values, not JSON. This creates the correct format.
    const formData = new URLSearchParams();
    formData.append('username', email); // Your backend code uses 'username'
    formData.append('password', password);

    try {
        // IMPORTANT: Ensure this matches your backend login endpoint.
        const response = await fetch(`${apiUrl}/login`, {
            method: 'POST',
            // The browser automatically sets Content-Type to 'application/x-www-form-urlencoded'
            body: formData,
            // Crucial for allowing the browser to set the session cookie from the response
            credentials: 'include',
        });

        // If the response is OK, the server has set the session cookie.
        if (response.ok) {
            isAuthenticated = true;
            return { success: true };
        } else {
            // Try to get the plain text error message from the backend response
            const errorMessage = await response.text();
            throw new Error(errorMessage || `Login failed with status: ${response.status}`);
        }
    } catch (error) {
        console.error('Login error:', error);
        isAuthenticated = false;
        return { success: false, message: error.message };
    }
}

/**
 * Logs the user out by calling the backend logout endpoint.
 */
export async function logout() {
    const apiUrl = getApiUrl();
    if (!apiUrl) return;

    try {
        // IMPORTANT: Your backend needs a '/logout' endpoint to clear the server-side session.
        await fetch(`${apiUrl}/logout`, {
            method: 'POST', // Or GET, depending on your backend implementation
            credentials: 'include',
        });
    } catch (error) {
        console.error('Logout error:', error);
    } finally {
        // Always update the auth state on the client regardless of server response
        isAuthenticated = false;
    }
}

/**
 * Checks the in-memory flag for authentication status.
 * This flag is set by checkAuthentication() or login().
 * @returns {boolean} - True if the user is considered logged in.
 */
export function isLoggedIn() {
    return isAuthenticated;
}

/**
 * Saves the API URL to localStorage.
 * @param {string} url - The base URL for the backend API.
 */
export function saveApiUrl(url) {
    localStorage.setItem(API_URL_KEY, url);
}

/**
 * Retrieves the API URL from localStorage.
 * @returns {string|null} - The stored URL, or null if not found.
 */
export function getApiUrl() {
    return localStorage.getItem(API_URL_KEY);
}
