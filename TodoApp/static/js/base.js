// Add Todo JS
const todoForm = document.getElementById("todoForm");
if (todoForm) {
  todoForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    const form = event.target;
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());

    const payload = {
      title: data.title,
      description: data.description,
      priority: parseInt(data.priority),
      complete: false,
    };

    try {
      const response = await fetchWithTokenRefresh("/todos/todo", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": getCsrfToken(),
        },
        body: JSON.stringify(payload),
      });

      if (response.ok) {
        form.reset(); // Clear the form
      } else {
        // Handle error
        const errorData = await response.json();
        alert(`Error: ${sanitizeClientSide(errorData.detail)}`);
      }
    } catch (error) {
      console.error("Error:", error);
      alert("An error occurred. Please try again.");
    }
  });
}

// Edit Todo JS
const editTodoForm = document.getElementById("editTodoForm");
if (editTodoForm) {
  editTodoForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());
    var url = window.location.pathname;
    const todoId = url.substring(url.lastIndexOf("/") + 1);

    const payload = {
      title: data.title,
      description: data.description,
      priority: parseInt(data.priority),
      complete: data.complete === "on",
    };

    try {
      const response = await fetchWithTokenRefresh(`/todos/todo/${todoId}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": getCsrfToken(),
        },
        body: JSON.stringify(payload),
      });

      if (response.ok) {
        window.location.href = "/todos/todo-page"; // Redirect to the todo page
      } else {
        // Handle error
        const errorData = await response.json();
        alert(`Error: ${sanitizeClientSide(errorData.detail)}`);
      }
    } catch (error) {
      console.error("Error:", error);
      alert("An error occurred. Please try again.");
    }
  });

  document.getElementById("deleteButton").addEventListener("click", async function () {
    var url = window.location.pathname;
    const todoId = url.substring(url.lastIndexOf("/") + 1);

    try {
      const response = await fetchWithTokenRefresh(`/todos/todo/${todoId}`, {
        method: "DELETE",
        headers: {
          "X-CSRF-Token": getCsrfToken(),
        },
      });

      if (response.ok) {
        // Handle success
        window.location.href = "/todos/todo-page"; // Redirect to the todo page
      } else {
        // Handle error
        const errorData = await response.json();
        alert(`Error: ${sanitizeClientSide(errorData.detail)}`);
      }
    } catch (error) {
      console.error("Error:", error);
      alert("An error occurred. Please try again.");
    }
  });
}

// Login JS
const loginForm = document.getElementById("loginForm");
if (loginForm) {
  // Function to show error message in the alert div
  function showLoginError(message) {
    const alertDiv = document.getElementById("loginAlert");
    if (alertDiv) {
      alertDiv.textContent = sanitizeClientSide(message);
      alertDiv.style.display = "block";
    } else {
      // Fallback to alert if the div is not found
      alert(sanitizeClientSide(message));
    }
  }

  // Function to hide the error message
  function hideLoginError() {
    const alertDiv = document.getElementById("loginAlert");
    if (alertDiv) {
      alertDiv.style.display = "none";
    }
  }

  loginForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    hideLoginError();

    const form = event.target;
    const formData = new FormData(form);

    const payload = new URLSearchParams();
    for (const [key, value] of formData.entries()) {
      payload.append(key, value);
    }

    try {
      const response = await fetch("/auth/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "X-CSRF-Token": getCsrfToken(),
        },
        body: payload.toString(),
      });

      if (response.ok) {
        // Handle success (e.g., redirect to dashboard)
        const data = await response.json();
        // No need to set cookie here as it's now set by the server with HttpOnly and Secure flags

        // Schedule token refresh
        scheduleTokenRefresh();

        // Start inactivity check
        startInactivityCheck();

        window.location.href = "/todos/todo-page"; // Change this to your desired redirect page
      } else {
        // Handle error based on status code
        const errorData = await response.json();

        if (response.status === 429) {
          // Rate limiting error - show specific message
          showLoginError(`Too many failed login attempts: ${errorData.detail}`);
        } else {
          // Other errors
          showLoginError(`Error: ${errorData.detail}`);
        }
      }
    } catch (error) {
      console.error("Error:", error);
      showLoginError("An error occurred. Please try again.");
    }
  });
}

// Resend Verification Email JS
const resendVerificationForm = document.getElementById("resendVerificationForm");
if (resendVerificationForm) {
  // Function to show message in the resend alert div
  function showResendMessage(message, isError = false) {
    const alertDiv = document.getElementById("resendAlert");
    if (alertDiv) {
      alertDiv.textContent = sanitizeClientSide(message);
      alertDiv.className = isError ? "alert alert-danger mt-3" : "alert alert-success mt-3";
      alertDiv.style.display = "block";
    } else {
      // Fallback to alert if the div is not found
      alert(sanitizeClientSide(message));
    }
  }

  // Function to hide the message
  function hideResendMessage() {
    const alertDiv = document.getElementById("resendAlert");
    if (alertDiv) {
      alertDiv.style.display = "none";
    }
  }

  resendVerificationForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    hideResendMessage();

    const form = event.target;
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());

    try {
      const response = await fetchWithTokenRefresh("/auth/resend-verification", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": getCsrfToken(),
        },
        body: JSON.stringify({ email: data.email }),
      });

      const responseData = await response.json();

      if (response.ok) {
        // Show success message
        showResendMessage(responseData.message);
        form.reset(); // Clear the form
      } else {
        // Show error message
        showResendMessage(responseData.detail || responseData.message || "An error occurred", true);
      }
    } catch (error) {
      console.error("Error:", error);
      showResendMessage("An error occurred. Please try again.", true);
    }
  });
}

// Password validation functions
function hasUpperCase(str) {
  return /[A-Z]/.test(str);
}

function hasLowerCase(str) {
  return /[a-z]/.test(str);
}

function hasNumber(str) {
  return /[0-9]/.test(str);
}

function hasSpecialChar(str) {
  return /[!@#$%^&*(),.?":{}|<>]/.test(str);
}

function validatePasswordStrength(password) {
  const checks = {
    length: password.length >= 8,
    uppercase: hasUpperCase(password),
    lowercase: hasLowerCase(password),
    number: hasNumber(password),
    special: hasSpecialChar(password)
  };

  // Calculate strength as percentage (20% for each check)
  const strength = Object.values(checks).filter(Boolean).length * 20;

  return { checks, strength };
}

// Register JS
const registerForm = document.getElementById("registerForm");
if (registerForm) {
  const passwordInput = document.getElementById("password");
  const password2Input = document.getElementById("password2");
  const lengthCheck = document.getElementById("length-check");
  const uppercaseCheck = document.getElementById("uppercase-check");
  const lowercaseCheck = document.getElementById("lowercase-check");
  const numberCheck = document.getElementById("number-check");
  const specialCheck = document.getElementById("special-check");
  const progressBar = document.querySelector("#password-strength .progress-bar");
  const passwordMatch = document.getElementById("password-match");

  // Function to update password strength UI
  function updatePasswordStrength() {
    const password = passwordInput.value;
    const { checks, strength } = validatePasswordStrength(password);

    // Update requirement checks
    lengthCheck.className = checks.length ? "text-success" : "text-danger";
    uppercaseCheck.className = checks.uppercase ? "text-success" : "text-danger";
    lowercaseCheck.className = checks.lowercase ? "text-success" : "text-danger";
    numberCheck.className = checks.number ? "text-success" : "text-danger";
    specialCheck.className = checks.special ? "text-success" : "text-danger";

    // Update progress bar
    progressBar.style.width = `${strength}%`;

    // Update progress bar color based on strength
    if (strength < 40) {
      progressBar.className = "progress-bar bg-danger";
    } else if (strength < 80) {
      progressBar.className = "progress-bar bg-warning";
    } else {
      progressBar.className = "progress-bar bg-success";
    }
  }

  // Function to check if passwords match
  function checkPasswordsMatch() {
    const password = passwordInput.value;
    const password2 = password2Input.value;

    if (password2.length > 0) {
      if (password === password2) {
        password2Input.classList.remove("is-invalid");
        password2Input.classList.add("is-valid");
        passwordMatch.style.display = "none";
        return true;
      } else {
        password2Input.classList.remove("is-valid");
        password2Input.classList.add("is-invalid");
        passwordMatch.style.display = "block";
        return false;
      }
    }
    return false;
  }

  // Add event listeners
  if (passwordInput) {
    passwordInput.addEventListener("input", updatePasswordStrength);
    passwordInput.addEventListener("input", checkPasswordsMatch);
  }

  if (password2Input) {
    password2Input.addEventListener("input", checkPasswordsMatch);
  }

  // Function to show registration error message
  function showRegistrationError(message) {
    const errorDiv = document.getElementById("registrationError");
    if (errorDiv) {
      errorDiv.textContent = sanitizeClientSide(message);
      errorDiv.style.display = "block";
    } else {
      // Fallback to alert if the div is not found
      alert(sanitizeClientSide(message));
    }
  }

  // Function to hide registration error message
  function hideRegistrationError() {
    const errorDiv = document.getElementById("registrationError");
    if (errorDiv) {
      errorDiv.style.display = "none";
    }
  }

  // Function to show registration success message and hide the form
  function showRegistrationSuccess() {
    const successDiv = document.getElementById("registrationSuccess");
    const formElement = document.getElementById("registerForm");

    if (successDiv) {
      successDiv.style.display = "block";
    }

    if (formElement) {
      formElement.style.display = "none";
    }
  }

  registerForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    hideRegistrationError();

    const form = event.target;
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());

    // Validate password strength
    const { checks, strength } = validatePasswordStrength(data.password);
    const isStrongPassword = Object.values(checks).every(Boolean);

    if (!isStrongPassword) {
      showRegistrationError("Password does not meet all requirements");
      return;
    }

    if (data.password !== data.password2) {
      showRegistrationError("Passwords do not match");
      return;
    }

    const payload = {
      email: data.email,
      username: data.username,
      first_name: data.firstname,
      last_name: data.lastname,
      role: data.role,
      phone_number: data.phone_number,
      password: data.password,
    };

    try {
      const response = await fetchWithTokenRefresh("/auth", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": getCsrfToken(),
        },
        body: JSON.stringify(payload),
      });

      const responseData = await response.json();

      if (response.ok) {
        // Show success message and hide the form
        showRegistrationSuccess();
        // Scroll to the top of the page to ensure the message is visible
        window.scrollTo(0, 0);
      } else {
        // Show error message
        showRegistrationError(responseData.detail || responseData.message || "Registration failed");
      }
    } catch (error) {
      console.error("Error:", error);
      showRegistrationError("An error occurred. Please try again.");
    }
  });
}

// Client-side sanitization function to prevent XSS
function sanitizeClientSide(text) {
  if (!text) return "";

  // Create a temporary div element
  const tempDiv = document.createElement('div');

  // Set the text content (this automatically escapes HTML)
  tempDiv.textContent = text;

  // Return the escaped HTML
  return tempDiv.textContent;
}

// Initialize token refresh and inactivity check when the page loads
document.addEventListener('DOMContentLoaded', function() {
  // Check if user is logged in by making a lightweight request
  fetchWithTokenRefresh('/healthy')
    .then(response => {
      if (response.ok) {
        // User is logged in, schedule token refresh
        scheduleTokenRefresh();

        // Start inactivity check
        startInactivityCheck();

        // Check for timeout parameter in URL
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('timeout') === 'true') {
          // Show timeout message if the login page has a timeout parameter
          const loginAlert = document.getElementById("loginAlert");
          if (loginAlert && window.location.pathname.includes('/login-page')) {
            loginAlert.textContent = "Your session has timed out due to inactivity. Please log in again.";
            loginAlert.style.display = "block";
          }
        }
      }
    })
    .catch(error => {
      console.error('Error checking authentication status:', error);
    });
});

// Helper function to get a cookie by name
function getCookie(name) {
  let cookieValue = null;
  if (document.cookie && document.cookie !== "") {
    const cookies = document.cookie.split(";");
    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      if (cookie.substring(0, name.length + 1) === name + "=") {
        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
        break;
      }
    }
  }
  return cookieValue;
}

// Helper function to get CSRF token
function getCsrfToken() {
  // First try to get it from the window variable set in layout.html
  if (window.csrfToken) {
    return window.csrfToken;
  }

  // If not available, try to get it from the meta tag
  const metaTag = document.querySelector('meta[name="csrf-token"]');
  if (metaTag) {
    return metaTag.getAttribute('content');
  }

  // If still not available, try to get it from the cookie
  return getCookie('csrf_token');
}

// Token refresh mechanism
let isRefreshing = false;
let refreshPromise = null;
let refreshSubscribers = [];
let tokenRefreshTimeout = null;

// Session timeout mechanism
let lastActivityTime = Date.now();
const INACTIVITY_TIMEOUT = 30 * 60 * 1000; // 30 minutes in milliseconds
let inactivityCheckInterval = null;

// Function to update the last activity timestamp
function updateActivity() {
  lastActivityTime = Date.now();
}

// Function to check for inactivity and logout if needed
function checkInactivity() {
  const currentTime = Date.now();
  const inactiveTime = currentTime - lastActivityTime;

  if (inactiveTime >= INACTIVITY_TIMEOUT) {
    console.log('User inactive for too long, logging out');
    // Call logout with a reason
    logout('inactivity');
  }
}

// Function to start the inactivity check
function startInactivityCheck() {
  // Clear any existing interval
  if (inactivityCheckInterval) {
    clearInterval(inactivityCheckInterval);
  }

  // Set initial activity time
  updateActivity();

  // Check for inactivity every minute
  inactivityCheckInterval = setInterval(checkInactivity, 60 * 1000);

  // Add event listeners for user activity
  const activityEvents = ['mousedown', 'keypress', 'scroll', 'touchstart'];
  activityEvents.forEach(eventType => {
    document.addEventListener(eventType, updateActivity);
  });
}

// Function to refresh the access token
async function refreshAccessToken() {
  // If already refreshing, return the existing promise
  if (isRefreshing) {
    return refreshPromise;
  }

  isRefreshing = true;
  refreshPromise = fetch('/auth/refresh-token', {
    method: 'POST',
    headers: {
      'X-CSRF-Token': getCsrfToken()
    }
  })
  .then(response => {
    if (!response.ok) {
      throw new Error('Failed to refresh token');
    }
    return response.json();
  })
  .then(data => {
    // Notify all subscribers that the token has been refreshed
    refreshSubscribers.forEach(callback => callback());
    refreshSubscribers = [];

    // Schedule the next token refresh (5 minutes before expiration)
    scheduleTokenRefresh();

    return data;
  })
  .finally(() => {
    isRefreshing = false;
  });

  return refreshPromise;
}

// Function to schedule token refresh before the token expires
function scheduleTokenRefresh() {
  // Clear any existing timeout
  if (tokenRefreshTimeout) {
    clearTimeout(tokenRefreshTimeout);
  }

  // Schedule refresh for 15 minutes from now (5 minutes before the 20-minute expiration)
  tokenRefreshTimeout = setTimeout(() => {
    refreshAccessToken().catch(error => {
      console.error('Scheduled token refresh failed:', error);
      // If refresh fails, redirect to login page
      window.location.href = '/auth/login-page';
    });
  }, 15 * 60 * 1000); // 15 minutes in milliseconds
}

// Function to add a subscriber to be notified when the token is refreshed
function subscribeTokenRefresh(callback) {
  refreshSubscribers.push(callback);
}

// Enhanced fetch function that handles token refresh
async function fetchWithTokenRefresh(url, options = {}) {
  // First attempt with current token
  const response = await fetch(url, options);

  // If unauthorized, try to refresh the token and retry
  if (response.status === 401) {
    try {
      // Refresh the token
      await refreshAccessToken();

      // Retry the original request with the new token
      return fetch(url, options);
    } catch (error) {
      console.error('Token refresh failed:', error);
      // If refresh fails, redirect to login
      window.location.href = '/auth/login-page';
      throw error;
    }
  }

  return response;
}

async function logout(reason = '') {
  // Clear the token refresh timeout
  if (tokenRefreshTimeout) {
    clearTimeout(tokenRefreshTimeout);
    tokenRefreshTimeout = null;
  }

  // Clear the inactivity check interval
  if (inactivityCheckInterval) {
    clearInterval(inactivityCheckInterval);
    inactivityCheckInterval = null;
  }

  // Remove activity event listeners
  const activityEvents = ['mousedown', 'keypress', 'scroll', 'touchstart'];
  activityEvents.forEach(eventType => {
    document.removeEventListener(eventType, updateActivity);
  });

  try {
    // Call the server-side logout endpoint to clear the HttpOnly cookie
    const response = await fetchWithTokenRefresh("/auth/logout", {
      method: "GET",
      headers: {
        "X-CSRF-Token": getCsrfToken(),
      },
    });

    if (response.ok) {
      // Also clear any non-HttpOnly cookies that might be set by JavaScript
      const cookies = document.cookie.split(";");
      for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i];
        const eqPos = cookie.indexOf("=");
        const name = eqPos > -1 ? cookie.substr(0, eqPos) : cookie;
        document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/";
      }

      // Redirect to the login page with a reason parameter if provided
      if (reason === 'inactivity') {
        window.location.href = "/auth/login-page?timeout=true";
      } else {
        window.location.href = "/auth/login-page";
      }
    } else {
      console.error("Logout failed");
      // Redirect anyway
      if (reason === 'inactivity') {
        window.location.href = "/auth/login-page?timeout=true";
      } else {
        window.location.href = "/auth/login-page";
      }
    }
  } catch (error) {
    console.error("Error during logout:", error);
    // Redirect anyway
    if (reason === 'inactivity') {
      window.location.href = "/auth/login-page?timeout=true";
    } else {
      window.location.href = "/auth/login-page";
    }
  }
}
