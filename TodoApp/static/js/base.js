// Generic form submission handler
async function handleFormSubmit(url, method, formData, contentType = "application/json", successCallback = null, errorCallback = null) {
    try {
        // Prepare headers based on the content type
        const headers = {
            "X-CSRF-Token": getCsrfToken(),
        };

        if (contentType) {
            headers["Content-Type"] = contentType;
        }

        // Prepare request options
        const requestOptions = {
            method: method,
            headers: headers,
        };

        // Add body if not GET request
        if (method !== "GET" && formData) {
            requestOptions.body = contentType === "application/json"
                ? JSON.stringify(formData)
                : formData;
        }

        // Make the request
        const response = await fetchWithTokenRefresh(url, requestOptions);

        // Handle response
        if (response.ok) {
            if (successCallback) {
                successCallback(response);
            }
            return {success: true, response};
        } else {
            // Parse error data
            const errorData = await response.json();

            if (errorCallback) {
                errorCallback(errorData, response.status);
            } else {
                // Default error handling with improved formatting
                const errorMessage = errorData.detail || "An error occurred";

                // Check if there's an error container on the page
                const errorContainer = document.querySelector(".alert-danger");
                if (errorContainer) {
                    // Display error in the container with better formatting
                    errorContainer.innerHTML = `<strong>Error:</strong> ${sanitizeClientSide(errorMessage)}`;
                    errorContainer.style.display = "block";

                    // Scroll to the error message
                    errorContainer.scrollIntoView({ behavior: 'smooth', block: 'center' });
                } else {
                    // Fallback to alert if no container is found
                    alert(`Error: ${sanitizeClientSide(errorMessage)}`);
                }
            }
            return {success: false, error: errorData, status: response.status};
        }
    } catch (error) {
        console.error("Error:", error);

        // Create a more helpful error message based on the error type
        let errorMessage = "An error occurred while processing your request.";

        // Check for network errors
        if (error instanceof TypeError && error.message.includes('fetch')) {
            errorMessage = "Network error: Please check your internet connection and try again.";
        } else if (error.name === 'AbortError') {
            errorMessage = "Request timed out. Please try again later.";
        } else if (error.name === 'SyntaxError') {
            errorMessage = "There was a problem processing the server response. Please try again later.";
        }

        if (errorCallback) {
            errorCallback({detail: errorMessage}, 0);
        } else {
            // Default error handling with improved formatting
            const errorContainer = document.querySelector(".alert-danger");
            if (errorContainer) {
                // Display error in the container with better formatting
                errorContainer.innerHTML = `<strong>Error:</strong> ${sanitizeClientSide(errorMessage)}`;
                errorContainer.style.display = "block";

                // Scroll to the error message
                errorContainer.scrollIntoView({ behavior: 'smooth', block: 'center' });
            } else {
                // Fallback to alert if no container is found
                alert(`Error: ${sanitizeClientSide(errorMessage)}`);
            }
        }
        return {success: false, error};
    }
}

// Add Todo JS
const todoForm = document.getElementById("todoForm");
if (todoForm) {
    const titleInput = todoForm.querySelector('input[name="title"]');
    const descriptionInput = todoForm.querySelector('textarea[name="description"]');
    const priorityInput = todoForm.querySelector('select[name="priority"]');

    // Add input validation on blur
    if (titleInput) {
        titleInput.addEventListener('blur', function () {
            const validation = validateTextField(this.value, 3, 50, "Title");
            showValidationFeedback(this, validation.isValid, validation.message);
        });
    }

    if (descriptionInput) {
        descriptionInput.addEventListener('blur', function () {
            const validation = validateTextField(this.value, 3, 500, "Description");
            showValidationFeedback(this, validation.isValid, validation.message);
        });
    }

    todoForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        const form = event.target;
        const formData = new FormData(form);
        const data = Object.fromEntries(formData.entries());

        // Validate form fields
        let isValid = true;

        // Validate title
        const titleValidation = validateTextField(data.title, 3, 50, "Title");
        isValid = showValidationFeedback(titleInput, titleValidation.isValid, titleValidation.message) && isValid;

        // Validate description
        const descriptionValidation = validateTextField(data.description, 3, 500, "Description");
        isValid = showValidationFeedback(descriptionInput, descriptionValidation.isValid, descriptionValidation.message) && isValid;

        // Validate priority
        if (!data.priority || isNaN(parseInt(data.priority)) || parseInt(data.priority) < 1 || parseInt(data.priority) > 5) {
            showValidationFeedback(priorityInput, false, "Please select a valid priority (1-5).");
            isValid = false;
        } else {
            showValidationFeedback(priorityInput, true, "");
        }

        if (!isValid) {
            // Show an error message
            const alertDiv = document.createElement("div");
            alertDiv.className = "alert alert-danger mt-3";
            alertDiv.textContent = "Please correct the errors in the form.";

            // Check if alert already exists
            const existingAlert = todoForm.querySelector(".alert");
            if (existingAlert) {
                existingAlert.remove();
            }

            // Insert alert at the top of the form
            todoForm.insertBefore(alertDiv, todoForm.firstChild);
            return;
        }

        const payload = {
            title: data.title,
            description: data.description,
            priority: parseInt(data.priority),
            complete: false,
        };

        const result = await handleFormSubmit(
            "/todos/todo",
            "POST",
            payload,
            "application/json",
            () => {
                form.reset(); // Clear the form
                window.location.href = "/todos/todo-page";
            }
        );
    });
}

// Edit Todo JS
const editTodoForm = document.getElementById("editTodoForm");
if (editTodoForm) {
    const titleInput = editTodoForm.querySelector('input[name="title"]');
    const descriptionInput = editTodoForm.querySelector('textarea[name="description"]');
    const priorityInput = editTodoForm.querySelector('select[name="priority"]');

    // Add input validation on blur
    if (titleInput) {
        titleInput.addEventListener('blur', function () {
            const validation = validateTextField(this.value, 3, 50, "Title");
            showValidationFeedback(this, validation.isValid, validation.message);
        });
    }

    if (descriptionInput) {
        descriptionInput.addEventListener('blur', function () {
            const validation = validateTextField(this.value, 3, 500, "Description");
            showValidationFeedback(this, validation.isValid, validation.message);
        });
    }

    editTodoForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        const form = event.target;
        const formData = new FormData(form);
        const data = Object.fromEntries(formData.entries());
        var url = window.location.pathname;
        const todoId = url.substring(url.lastIndexOf("/") + 1);

        // Validate form fields
        let isValid = true;

        // Validate title
        const titleValidation = validateTextField(data.title, 3, 50, "Title");
        isValid = showValidationFeedback(titleInput, titleValidation.isValid, titleValidation.message) && isValid;

        // Validate description
        const descriptionValidation = validateTextField(data.description, 3, 500, "Description");
        isValid = showValidationFeedback(descriptionInput, descriptionValidation.isValid, descriptionValidation.message) && isValid;

        // Validate priority
        if (!data.priority || isNaN(parseInt(data.priority)) || parseInt(data.priority) < 1 || parseInt(data.priority) > 5) {
            showValidationFeedback(priorityInput, false, "Please select a valid priority (1-5).");
            isValid = false;
        } else {
            showValidationFeedback(priorityInput, true, "");
        }

        if (!isValid) {
            // Show an error message
            const alertDiv = document.createElement("div");
            alertDiv.className = "alert alert-danger mt-3";
            alertDiv.textContent = "Please correct the errors in the form.";

            // Check if the alert already exists
            const existingAlert = editTodoForm.querySelector(".alert");
            if (existingAlert) {
                existingAlert.remove();
            }

            // Insert an alert at the top of the form
            editTodoForm.insertBefore(alertDiv, editTodoForm.firstChild);
            return;
        }

        const payload = {
            title: data.title,
            description: data.description,
            priority: parseInt(data.priority),
            complete: data.complete === "on",
        };

        await handleFormSubmit(
            `/todos/todo/${todoId}`,
            "PUT",
            payload,
            "application/json",
            () => {
                window.location.href = "/todos/todo-page"; // Redirect to the todo page
            }
        );
    });

    document.getElementById("deleteButton").addEventListener("click", async function () {
        // Confirm deletion
        if (!confirm("Are you sure you want to delete this todo?")) {
            return; // User cancelled the deletion
        }

        var url = window.location.pathname;
        const todoId = url.substring(url.lastIndexOf("/") + 1);

        await handleFormSubmit(
            `/todos/todo/${todoId}`,
            "DELETE",
            null,
            null,
            () => {
                window.location.href = "/todos/todo-page"; // Redirect to the todo page
            }
        );
    });
}

// Utility function to show/hide messages in alert divs
function showMessage(elementId, message, isError = true) {
    const alertDiv = document.getElementById(elementId);
    if (alertDiv) {
        // Create enhanced message with icon and formatting
        const icon = isError 
            ? '<i class="fas fa-exclamation-circle" aria-hidden="true"></i>' 
            : '<i class="fas fa-check-circle" aria-hidden="true"></i>';

        const title = isError ? '<strong>Error:</strong> ' : '<strong>Success:</strong> ';

        // Set the HTML content with proper sanitization
        alertDiv.innerHTML = `${icon} ${title}${sanitizeClientSide(message)}`;

        // Add a dismiss button if it doesn't already have one
        if (!alertDiv.querySelector('.close')) {
            const dismissButton = document.createElement('button');
            dismissButton.type = 'button';
            dismissButton.className = 'close';
            dismissButton.setAttribute('aria-label', 'Close');
            dismissButton.innerHTML = '<span aria-hidden="true">&times;</span>';
            dismissButton.addEventListener('click', function() {
                alertDiv.style.display = 'none';
            });

            // Add the button to the alert
            alertDiv.prepend(dismissButton);
        }

        // Show the alert
        alertDiv.style.display = "block";

        // Update alert class if it has alert-success or alert-danger
        if (alertDiv.classList.contains("alert-success") || alertDiv.classList.contains("alert-danger")) {
            alertDiv.classList.remove("alert-success", "alert-danger");
            alertDiv.classList.add(isError ? "alert-danger" : "alert-success");
        }

        // Add alert-dismissible class if not already present
        if (!alertDiv.classList.contains("alert-dismissible")) {
            alertDiv.classList.add("alert-dismissible");
        }

        // Scroll to the alert
        alertDiv.scrollIntoView({ behavior: 'smooth', block: 'center' });
    } else {
        // Fallback to alert if the div is not found
        alert(sanitizeClientSide(message));
    }
}

function hideMessage(elementId) {
    const alertDiv = document.getElementById(elementId);
    if (alertDiv) {
        alertDiv.style.display = "none";
    }
}

// Function to validate reCAPTCHA
async function validateRecaptcha(errorMessageElementId) {
    // Check if reCAPTCHA script failed to load
    if (window.recaptchaLoadFailed) {
        console.error("reCAPTCHA failed to load");
        showMessage(errorMessageElementId, "reCAPTCHA could not be loaded. Please check your internet connection and try again.");
        return null;
    }

    // Check if grecaptcha is defined
    if (typeof grecaptcha === 'undefined') {
        console.error("reCAPTCHA not loaded");
        showMessage(errorMessageElementId, "reCAPTCHA could not be loaded. Please refresh the page and try again.");
        return null;
    }

    // Get the reCAPTCHA v2 response
    const recaptchaResponse = grecaptcha.getResponse();
    if (!recaptchaResponse) {
        showMessage(errorMessageElementId, "Please complete the reCAPTCHA verification.");
        return null;
    }

    return recaptchaResponse;
}

// Function to reset reCAPTCHA
function resetRecaptcha() {
    try {
        if (typeof grecaptcha !== 'undefined' && typeof grecaptcha.reset === 'function') {
            grecaptcha.reset();
        }
    } catch (resetError) {
        console.error("Error resetting reCAPTCHA:", resetError);
    }
}

// Login JS
const loginForm = document.getElementById("loginForm");
if (loginForm) {
    // Shorthand functions for login form messages
    function showLoginError(message) {
        showMessage("loginAlert", message, true);
    }

    function hideLoginError() {
        hideMessage("loginAlert");
    }

    // Add input validation on blur
    const usernameInput = loginForm.querySelector('input[name="username"]');
    const passwordInput = loginForm.querySelector('input[name="password"]');

    if (usernameInput) {
        usernameInput.addEventListener('blur', function () {
            const validation = validateUsername(this.value);
            showValidationFeedback(this, validation.isValid, validation.message);
        });
    }

    if (passwordInput) {
        passwordInput.addEventListener('blur', function () {
            const validation = validateTextField(this.value, 8, 100, "Password");
            showValidationFeedback(this, validation.isValid, validation.message);
        });
    }

    loginForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        hideLoginError();

        const form = event.target;
        const formData = new FormData(form);
        const username = formData.get('username');
        const password = formData.get('password');

        // Validate form fields
        let isValid = true;

        // Validate username
        const usernameValidation = validateUsername(username);
        isValid = showValidationFeedback(usernameInput, usernameValidation.isValid, usernameValidation.message) && isValid;

        // Validate password
        const passwordValidation = validateTextField(password, 8, 100, "Password");
        isValid = showValidationFeedback(passwordInput, passwordValidation.isValid, passwordValidation.message) && isValid;

        if (!isValid) {
            showLoginError("Please correct the errors in the form.");
            return;
        }

        // Create URL-encoded payload
        const payload = new URLSearchParams();
        for (const [key, value] of formData.entries()) {
            payload.append(key, value);
        }

        // Validate reCAPTCHA
        const recaptchaResponse = await validateRecaptcha("loginAlert");
        if (!recaptchaResponse) {
            return; // Validation failed
        }

        // Custom success handler for login
        const handleLoginSuccess = async (response) => {
            const data = await response.json();

            // Check if 2FA is required
            if (data.requires_2fa) {
                // Redirect to 2FA verification page
                window.location.href = data.redirect_url;
                return;
            }

            // Schedule token refresh
            scheduleTokenRefresh();

            // Start inactivity check
            startInactivityCheck();

            // Redirect to td page
            window.location.href = "/todos/todo-page";
        };

        // Custom error handler for login
        const handleLoginError = (errorData, status) => {
            if (status === 429) {
                // Rate limiting error - show specific message with guidance
                showLoginError(`${errorData.detail} Please wait before trying again or use the password reset option if you've forgotten your password.`);
            } else if (status === 401) {
                // Authentication error - could be wrong credentials or unverified email
                if (errorData.detail && errorData.detail.includes("email")) {
                    // Email verification issue
                    showLoginError(errorData.detail);

                    // Automatically expand the verification help section
                    const verificationHelp = document.getElementById("verificationHelp");
                    if (verificationHelp) {
                        verificationHelp.classList.add("show");
                    }
                } else {
                    // Other authentication errors
                    showLoginError(errorData.detail);
                }
            } else if (status === 400 && errorData.detail && errorData.detail.includes("reCAPTCHA")) {
                // reCAPTCHA error
                showLoginError(errorData.detail);

                // Reset the reCAPTCHA
                resetRecaptcha();
            } else {
                // Other errors
                showLoginError(errorData.detail || "An error occurred during login. Please try again.");
            }
        };

        try {
            // Submit the form
            await handleFormSubmit(
                `/auth/token?g_recaptcha_response=${encodeURIComponent(recaptchaResponse)}`,
                "POST",
                payload.toString(),
                "application/x-www-form-urlencoded",
                handleLoginSuccess,
                handleLoginError
            );
        } catch (error) {
            console.error("Error:", error);
            showLoginError("An error occurred. Please try again.");
        } finally {
            // Reset the reCAPTCHA widget
            resetRecaptcha();
        }
    });
}

// Resend Verification Email JS
const resendVerificationForm = document.getElementById("resendVerificationForm");
if (resendVerificationForm) {
    // Shorthand functions for resend verification form messages
    function showResendMessage(message, isError = false) {
        showMessage("resendAlert", message, isError);
    }

    function hideResendMessage() {
        hideMessage("resendAlert");
    }

    // Get the email input element
    const emailInput = resendVerificationForm.querySelector('input[name="email"]');

    // Add validation on blur
    if (emailInput) {
        emailInput.addEventListener('blur', function () {
            const validation = validateEmail(this.value);
            showValidationFeedback(this, validation.isValid, validation.message);
        });
    }

    resendVerificationForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        hideResendMessage();

        const form = event.target;
        const formData = new FormData(form);
        const data = Object.fromEntries(formData.entries());

        // Validate email
        const emailValidation = validateEmail(data.email);
        const isValid = showValidationFeedback(emailInput, emailValidation.isValid, emailValidation.message);

        if (!isValid) {
            showResendMessage("Please enter a valid email address.", true);
            return;
        }

        // Custom success handler for resend verification
        const handleResendSuccess = async (response) => {
            const responseData = await response.json();
            showResendMessage(responseData.message, false);
            form.reset(); // Clear the form

            // Reset validation state
            emailInput.classList.remove("is-valid", "is-invalid");
            const feedbackElement = emailInput.nextElementSibling;
            if (feedbackElement && feedbackElement.classList.contains("invalid-feedback")) {
                feedbackElement.textContent = "";
            }
        };

        // Custom error handler for resend verification
        const handleResendError = (errorData) => {
            showResendMessage(errorData.detail || errorData.message || "An error occurred", true);
        };

        // Submit the form
        await handleFormSubmit(
            "/auth/resend-verification",
            "POST",
            {email: data.email},
            "application/json",
            handleResendSuccess,
            handleResendError
        );
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

    return {checks, strength};
}

// Register JS
const registerForm = document.getElementById("registerForm");
if (registerForm) {
    const emailInput = registerForm.querySelector('input[name="email"]');
    const usernameInput = registerForm.querySelector('input[name="username"]');
    const firstnameInput = registerForm.querySelector('input[name="firstname"]');
    const lastnameInput = registerForm.querySelector('input[name="lastname"]');
    const phoneInput = registerForm.querySelector('input[name="phone_number"]');
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
        const {checks, strength} = validatePasswordStrength(password);

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

    // Add event listeners for blur validation
    if (emailInput) {
        emailInput.addEventListener('blur', function () {
            const validation = validateEmail(this.value);
            showValidationFeedback(this, validation.isValid, validation.message);
        });
    }

    if (usernameInput) {
        usernameInput.addEventListener('blur', function () {
            const validation = validateUsername(this.value);
            showValidationFeedback(this, validation.isValid, validation.message);
        });
    }

    if (firstnameInput) {
        firstnameInput.addEventListener('blur', function () {
            const validation = validateName(this.value);
            showValidationFeedback(this, validation.isValid, validation.message);
        });
    }

    if (lastnameInput) {
        lastnameInput.addEventListener('blur', function () {
            const validation = validateName(this.value);
            showValidationFeedback(this, validation.isValid, validation.message);
        });
    }

    if (phoneInput) {
        phoneInput.addEventListener('blur', function () {
            const validation = validatePhoneNumber(this.value);
            showValidationFeedback(this, validation.isValid, validation.message);
        });
    }

    // Add event listeners for password validation
    if (passwordInput) {
        passwordInput.addEventListener("input", updatePasswordStrength);
        passwordInput.addEventListener("input", checkPasswordsMatch);
    }

    if (password2Input) {
        password2Input.addEventListener("input", checkPasswordsMatch);
    }

    // Shorthand functions for registration form messages
    function showRegistrationError(message) {
        showMessage("registrationError", message, true);
    }

    function hideRegistrationError() {
        hideMessage("registrationError");
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

        // Scroll to the top of the page to ensure the message is visible
        window.scrollTo(0, 0);
    }

    registerForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        hideRegistrationError();

        const form = event.target;
        const formData = new FormData(form);
        const data = Object.fromEntries(formData.entries());

        // Validate all form fields
        let isValid = true;

        // Validate email
        const emailValidation = validateEmail(data.email);
        isValid = showValidationFeedback(emailInput, emailValidation.isValid, emailValidation.message) && isValid;

        // Validate username
        const usernameValidation = validateUsername(data.username);
        isValid = showValidationFeedback(usernameInput, usernameValidation.isValid, usernameValidation.message) && isValid;

        // Validate first name
        const firstnameValidation = validateName(data.firstname);
        isValid = showValidationFeedback(firstnameInput, firstnameValidation.isValid, firstnameValidation.message) && isValid;

        // Validate last name
        const lastnameValidation = validateName(data.lastname);
        isValid = showValidationFeedback(lastnameInput, lastnameValidation.isValid, lastnameValidation.message) && isValid;

        // Validate phone number
        const phoneValidation = validatePhoneNumber(data.phone_number);
        isValid = showValidationFeedback(phoneInput, phoneValidation.isValid, phoneValidation.message) && isValid;

        // Validate password strength
        const {checks, strength} = validatePasswordStrength(data.password);
        const isStrongPassword = Object.values(checks).every(Boolean);

        if (!isStrongPassword) {
            showRegistrationError("Password does not meet all requirements");
            isValid = false;
        }

        // Validate password match
        if (data.password !== data.password2) {
            showRegistrationError("Passwords do not match");
            password2Input.classList.add("is-invalid");
            isValid = false;
        }

        if (!isValid) {
            showRegistrationError("Please correct the errors in the form.");
            return;
        }

        // Create a JSON payload with all the user data
        const payload = {
            email: data.email,
            username: data.username,
            first_name: data.firstname,
            last_name: data.lastname,
            phone_number: data.phone_number,
            password: data.password,
        };

        // Validate reCAPTCHA
        const recaptchaResponse = await validateRecaptcha("registrationError");
        if (!recaptchaResponse) {
            return; // Validation failed
        }

        // Custom success handler for registration
        const handleRegistrationSuccess = () => {
            showRegistrationSuccess();
        };

        // Custom error handler for registration
        const handleRegistrationError = (errorData, status) => {
            // Extract the error message
            const errorMessage = errorData.detail || errorData.message || "Registration failed";

            // Handle specific registration errors with helpful guidance
            if (errorMessage.includes("email") && errorMessage.includes("registered")) {
                // Email already registered
                showRegistrationError(errorMessage + " You can try logging in or use the 'Forgot Password' option if needed.");

                // Highlight the email field
                if (emailInput) {
                    emailInput.classList.add("is-invalid");
                    const feedbackElement = emailInput.nextElementSibling;
                    if (feedbackElement && feedbackElement.classList.contains("invalid-feedback")) {
                        feedbackElement.textContent = "This email is already registered.";
                    }
                }
            } else if (errorMessage.includes("username") && errorMessage.includes("taken")) {
                // Username already taken
                showRegistrationError(errorMessage);

                // Highlight the username field
                if (usernameInput) {
                    usernameInput.classList.add("is-invalid");
                    const feedbackElement = usernameInput.nextElementSibling;
                    if (feedbackElement && feedbackElement.classList.contains("invalid-feedback")) {
                        feedbackElement.textContent = "This username is already taken.";
                    }
                }
            } else if (errorMessage.includes("password")) {
                // Password validation error
                showRegistrationError(errorMessage);

                // Highlight the password field
                if (passwordInput) {
                    passwordInput.classList.add("is-invalid");
                }
            } else if (errorMessage.includes("reCAPTCHA") || errorMessage.includes("security verification")) {
                // reCAPTCHA error
                showRegistrationError(errorMessage);

                // Reset the reCAPTCHA
                resetRecaptcha();
            } else {
                // Other errors
                showRegistrationError(errorMessage);
            }
        };

        try {
            // Submit the form
            await handleFormSubmit(
                `/auth?g_recaptcha_response=${encodeURIComponent(recaptchaResponse)}`,
                "POST",
                payload,
                "application/json",
                handleRegistrationSuccess,
                handleRegistrationError
            );
        } catch (error) {
            console.error("Error:", error);
            showRegistrationError("An error occurred. Please try again.");
        } finally {
            // Reset the reCAPTCHA widget
            resetRecaptcha();
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

// Validation functions
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return {
        isValid: emailRegex.test(email),
        message: emailRegex.test(email) ? "" : "Please enter a valid email address."
    };
}

function validateUsername(username) {
    // Username should be 3-20 characters and contain only letters, numbers, underscores, and hyphens
    const usernameRegex = /^[a-zA-Z0-9_-]{3,20}$/;
    return {
        isValid: usernameRegex.test(username),
        message: usernameRegex.test(username) ? "" : "Username must be 3-20 characters and may only contain letters, numbers, underscores, and hyphens."
    };
}

function validatePhoneNumber(phoneNumber) {
    // Basic phone number validation - allows various formats
    const phoneRegex = /^[\d\s\+\-\(\)]{10,15}$/;
    return {
        isValid: phoneRegex.test(phoneNumber),
        message: phoneRegex.test(phoneNumber) ? "" : "Please enter a valid phone number."
    };
}

function validateName(name) {
    // Name should be at least 2 characters and contain only letters, spaces, hyphens, and apostrophes
    const nameRegex = /^[a-zA-Z\s'-]{2,}$/;
    return {
        isValid: nameRegex.test(name),
        message: nameRegex.test(name) ? "" : "Name must be at least 2 characters and contain only letters, spaces, hyphens, and apostrophes."
    };
}

function validateTextField(text, minLength, maxLength, fieldName) {
    if (!text || text.trim() === "") {
        return {
            isValid: false,
            message: `${fieldName} is required.`
        };
    }

    if (minLength && text.length < minLength) {
        return {
            isValid: false,
            message: `${fieldName} must be at least ${minLength} characters.`
        };
    }

    if (maxLength && text.length > maxLength) {
        return {
            isValid: false,
            message: `${fieldName} cannot exceed ${maxLength} characters.`
        };
    }

    return {
        isValid: true,
        message: ""
    };
}

// Function to show validation feedback
function showValidationFeedback(inputElement, isValid, message) {
    // Remove existing validation classes
    inputElement.classList.remove("is-valid", "is-invalid");

    // Add appropriate validation class
    inputElement.classList.add(isValid ? "is-valid" : "is-invalid");

    // Find or create feedback element
    let feedbackElement = inputElement.nextElementSibling;
    if (!feedbackElement || !feedbackElement.classList.contains("invalid-feedback")) {
        feedbackElement = document.createElement("div");
        feedbackElement.className = "invalid-feedback";
        inputElement.parentNode.insertBefore(feedbackElement, inputElement.nextSibling);
    }

    // Set feedback message
    feedbackElement.textContent = message;

    return isValid;
}

// Initialize token refresh and inactivity check when the page loads
document.addEventListener('DOMContentLoaded', function () {
    // Check if a user is logged in by making a lightweight request
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
                    // Show a timeout message if the login page has a timeout parameter
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
    // First, try to get it from the window variable set in layout.html
    if (window.csrfToken) {
        return window.csrfToken;
    }

    // If not available, try to get it from the meta-tag
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

    // Set the initial activity time
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
    // Skip token refresh for login and token endpoints
    if (response.status === 401 && !url.includes('/auth/token') && !url.includes('/auth/refresh-token')) {
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
