# SecureTodo - A Secure Todo Application

SecureTodo is a robust, security-focused Todo application built with FastAPI. It implements modern security best practices to protect user data and prevent common web vulnerabilities.

## Features

### Authentication & User Management
- Secure user registration with email verification
- Login with username/password
- Two-factor authentication (2FA) using TOTP
- Password reset via email
- User profile management
- Session management with JWT tokens
- Automatic token refresh

### Todo Management
- Create, read, update, and delete todo items
- Todo prioritization
- Mark todos as complete/incomplete
- User-specific todo lists

### Security Features
- Content Security Policy (CSP) implementation
- HTTP Security Headers (HSTS, Permissions-Policy, X-Content-Type-Options, etc.)
- Cross-Site Request Forgery (CSRF) protection
- Input sanitization to prevent XSS attacks
- Password strength validation
- Rate limiting for login attempts
- Secure cookie handling with HttpOnly and Secure flags
- JWT token-based authentication
- Database connection pooling
- Comprehensive error handling and logging
- Email verification for account changes
- Secure password hashing with bcrypt

### Admin Features
- View all todos across users
- Delete any todo item
- User management (future enhancement)

## Documentation

- **Flowcharts**: Comprehensive flowcharts showing the application architecture and user flows are available in the [docs/flowchart.md](docs/flowchart.md) file. These include:
  - Application Architecture
  - Authentication Flow
  - Todo Management Flow
  - Admin Flow

## Technologies Used

- **Backend**: FastAPI, Python 3.8+
- **Database**: SQLite with SQLAlchemy ORM
- **Authentication**: JWT tokens, Passlib, PyOTP
- **Frontend**: HTML, CSS, JavaScript, Bootstrap
- **Email**: SMTP with Python's email library
- **Security**: CSP, CSRF protection, input sanitization
- **Testing**: Pytest

## Installation and Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation Steps

1. Clone the repository
   ```bash
   git clone https://github.com/LorenMin107/TodoApp.git
   cd TodoApp
   ```

2. Create and activate a virtual environment
   ```bash
   # Windows
   python3 -m venv fastapienv
   fastapienv\Scripts\activate

   # macOS/Linux
   python3 -m venv fastapienv
   source fastapienv/bin/activate
   ```

3. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables by creating a `.env` file in the project root:
   ```
   # Email Configuration
   SMTP_SERVER=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USERNAME=your_email@gmail.com
   SMTP_PASSWORD=your_app_password
   EMAIL_FROM=your_email@gmail.com
   APP_BASE_URL=http://localhost:8000

   # JWT Secret Key
   SECRET_KEY=your_secure_random_key_here

   # Database Configuration
   DB_NAME=todosapp.db

   # reCAPTCHA Configuration (optional)
   RECAPTCHA_SITE_KEY=your_recaptcha_site_key
   RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key
   ```

   c. Generate a secure random key for SECRET_KEY using Python:
   ```python
   import secrets
   print(secrets.token_hex(32))  # Generates a 64-character hex string
   ```

   > **IMPORTANT**: The `.env` file contains sensitive information and should **never** be committed to version control. 
   > The repository includes a `.gitignore` file that excludes `.env` files by default.

5. Run the application (make sure you're in the root directory of the project)
   ```bash

   #Using Python module
   python3 -m TodoApp.main
   ```

6. Access the application at http://localhost:8000

### Setting Up Gmail for Email Verification

If you're using Gmail for sending verification emails:

1. Enable 2-factor authentication on your Google account
2. Generate an App Password at https://myaccount.google.com/apppasswords
3. Use that App Password in your `.env` file instead of your regular password

## Usage

### User Registration and Login
1. Navigate to the registration page and create an account
2. Verify your email address by clicking the link sent to your email
3. Log in with your credentials
4. (Optional) Set up two-factor authentication for enhanced security

### Managing Todos
1. Create new todos with a title, description, and priority
2. View your list of todos
3. Edit existing todos
4. Mark todos as complete
5. Delete todos you no longer need

### User Profile Management
1. View your profile information
2. Change your password
3. Update your phone number
4. Enable or disable two-factor authentication

### Admin Functions
If you have admin privileges:
1. View todos from all users
2. Delete any todo item

## Security Best Practices Implemented

- **Password Security**: Passwords are hashed using bcrypt and validated for strength
- **JWT Security**: Short-lived access tokens with refresh mechanism
- **XSS Prevention**: Content Security Policy and input sanitization
- **CSRF Protection**: Token-based CSRF protection for all state-changing operations
- **Rate Limiting**: Protection against brute force attacks
- **Secure Cookies**: HttpOnly and Secure flags to protect cookies
- **2FA**: Optional two-factor authentication using TOTP
- **Email Verification**: Account changes require email verification
- **Input Validation**: All user inputs are validated and sanitized
- **Error Handling**: Comprehensive error handling without leaking sensitive information
- **Environment Security**: Sensitive configuration stored in environment variables, not in code
- **Secret Management**: Critical secrets like JWT keys are required from environment variables with no fallbacks
- **HTTP Security Headers**: 
  - Strict-Transport-Security (HSTS): Forces HTTPS connections
  - Permissions-Policy: Restricts access to sensitive browser features
  - X-Content-Type-Options: Prevents MIME type sniffing
  - X-Frame-Options: Prevents clickjacking attacks
  - Referrer-Policy: Controls how much referrer information is included
  - X-XSS-Protection: Enables browser's built-in XSS filtering

## Acknowledgements

- FastAPI for the amazing web framework
- SQLAlchemy for the ORM
- PyJWT for JWT token handling
- PyOTP for two-factor authentication
- Bootstrap for the frontend styling
- Passlib for password hashing
- Python's email library for sending emails
- SQLite for the database
- pytest for testing
- CSP and CSRF libraries for security
- dotenv for environment variable management
- email-validator for email validation
