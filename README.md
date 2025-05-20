# TodoApp

A FastAPI-based Todo application with user authentication and task management features.

## Setup and Installation

1. Clone the repository
2. Create a virtual environment: `python -m venv fastapienv`
3. Activate the virtual environment:
   - Windows: `fastapienv\Scripts\activate`
   - macOS/Linux: `source fastapienv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Set environment variables (see below)
6. Run the application: `uvicorn TodoApp.main:app --reload`

## Environment Variables

For security reasons, sensitive information should be stored in environment variables rather than in the code. The application uses a `.env` file to manage environment variables locally.

### Required Environment Variables

- `SECRET_KEY`: Used for JWT token encryption. Generate a secure random key for production.

### Database Configuration

The application uses SQLite as the database. Configure the following database-related environment variable in the `.env` file:

- `DB_NAME`: The database name (default: todosapp.db)

### Email Verification Configuration

For email verification to work, you need to configure the following email-related environment variables in the `.env` file:

- `SMTP_SERVER`: The SMTP server address (default: smtp.gmail.com)
- `SMTP_PORT`: The SMTP server port (default: 587)
- `SMTP_USERNAME`: Your email address
- `SMTP_PASSWORD`: Your email password or app password (for Gmail)
- `EMAIL_FROM`: The email address that verification emails will be sent from (usually the same as SMTP_USERNAME)
- `APP_BASE_URL`: The base URL of your application (default: http://localhost:8000)

### Setting Up Gmail for Email Verification

If you're using Gmail, you need to:

1. Enable 2-factor authentication on your Google account
2. Generate an App Password at https://myaccount.google.com/apppasswords
3. Use that App Password in your `.env` file instead of your regular password

### Example .env File

Create a file named `.env` in the project root with the following content:

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
```

### Setting Environment Variables Manually

If you prefer not to use a `.env` file, you can set these variables manually:

#### Windows
```
set SECRET_KEY=your_secure_random_key_here
set SMTP_USERNAME=your_email@gmail.com
set SMTP_PASSWORD=your_app_password
set EMAIL_FROM=your_email@gmail.com
set DB_NAME=todosapp.db
```

#### macOS/Linux
```
export SECRET_KEY=your_secure_random_key_here
export SMTP_USERNAME=your_email@gmail.com
export SMTP_PASSWORD=your_app_password
export EMAIL_FROM=your_email@gmail.com
export DB_NAME=todosapp.db
```

#### In Production
In production environments, set these environment variables according to your deployment platform's documentation.

## Generating a Secure SECRET_KEY

You can generate a secure random key using Python:

```python
import secrets
print(secrets.token_hex(32))  # Generates a 64-character hex string
```

## Features

- User authentication with JWT tokens
- Email verification for new user registrations
- Todo item management (create, read, update, delete)
- User role-based access control
- Password strength requirements
- CSRF protection
- Rate limiting for login attempts
- Secure cookie handling with HttpOnly and Secure flags
- Content Security Policy (CSP) headers to prevent XSS attacks
- Additional security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy)
- Input sanitization to prevent XSS attacks
- JWT token refresh mechanism for seamless user experience
- Session timeout for inactive users (30 minutes)
- Secure password reset functionality with email verification
- Database connection pooling for improved performance
- SQLite database with configuration stored in environment variables for enhanced security
- Responsive web interface
