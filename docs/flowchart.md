# SecureTodo Application Flowchart

This document contains flowcharts representing the architecture and flow of the SecureTodo application.

## Application Architecture

```mermaid
graph TD
    %% Client Layer
    Client[Client Browser] --> |HTTP Request| FastAPI[FastAPI Application]

    %% Middleware Layer
    subgraph Middleware
        CSP[CSP Middleware]
        CSRF[CSRF Middleware]
    end
    FastAPI --> CSP
    FastAPI --> CSRF

    %% Router Layer
    subgraph Routers
        AuthRouter[Auth Router]
        TodosRouter[Todos Router]
        AdminRouter[Admin Router]
        UsersRouter[Users Router]
    end
    FastAPI --> AuthRouter
    FastAPI --> TodosRouter
    FastAPI --> AdminRouter
    FastAPI --> UsersRouter

    %% Auth Components
    subgraph Auth Modules
        Login[Login Module]
        Registration[Registration Module]
        PasswordReset[Password Reset Module]
        TwoFactor[Two-Factor Auth Module]
        TokenManager[Token Manager]
    end
    AuthRouter --> Login
    AuthRouter --> Registration
    AuthRouter --> PasswordReset
    AuthRouter --> TwoFactor
    AuthRouter --> TokenManager

    %% Security Components
    subgraph Security
        PasswordValidator[Password Validator]
        RateLimiter[Rate Limiter]
    end
    Login --> PasswordValidator
    Registration --> PasswordValidator
    PasswordReset --> PasswordValidator
    Login --> RateLimiter
    Registration --> RateLimiter

    %% Database Layer
    subgraph Database Layer
        Database[(Database)]
        Users[Users Model]
        Todos[Todos Model]
        ActivityLog[Activity Log Model]
        RevokedTokens[Revoked Tokens Model]
    end
    TodosRouter --> |CRUD Operations| Database
    AuthRouter --> |User Operations| Database
    AdminRouter --> |Admin Operations| Database
    UsersRouter --> |User Management| Database
    Database --> Users
    Database --> Todos
    Database --> ActivityLog
    Database --> RevokedTokens

    %% Utilities
    subgraph Utilities
        ActivityLogger[Activity Logger]
        Cache[Cache]
    end
    TodosRouter --> ActivityLogger
    AuthRouter --> ActivityLogger
    AdminRouter --> ActivityLogger
    UsersRouter --> ActivityLogger
    TodosRouter --> Cache

    %% Email
    subgraph Email
        EmailUtils[Email Utilities]
    end
    PasswordReset --> EmailUtils
    Registration --> EmailUtils
```

## Authentication Flow

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant App as SecureTodo App
    participant DB as Database

    %% Registration Flow
    User->>Browser: Opens register page
    Browser->>App: GET /auth/register-page
    App->>Browser: Return Registration Form
    User->>Browser: Submits registration form
    Browser->>App: POST /auth/register
    App->>App: Validates input
    App->>App: Hashes password
    App->>DB: Stores user
    App->>Browser: Redirects to login

    %% Login Flow with optional 2FA
    User->>Browser: Submits login form
    Browser->>App: POST /auth/login
    App->>DB: Verifies credentials

    alt 2FA is enabled
        App->>Browser: Redirect to 2FA page
        User->>Browser: Enter 2FA code
        Browser->>App: POST /auth/verify-2fa
        App->>App: Verifies 2FA code
    end

    App->>App: Issues JWT token
    App->>Browser: Set cookie & redirect to todos

    %% Password Reset Flow
    User->>Browser: Requests password reset
    Browser->>App: POST /auth/request-password-reset
    App->>App: Generates reset token
    App->>DB: Stores reset token
    App->>User: Sends email with reset link
    User->>Browser: Clicks reset link
    Browser->>App: GET /auth/reset-password/{token}
    App->>Browser: Return new password form
    User->>Browser: Sets new password
    Browser->>App: POST /auth/reset-password
    App->>App: Hashes new password
    App->>DB: Updates password
    App->>Browser: Redirects to login
```

## Todo Management Flow

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant App as SecureTodo App
    participant DB as Database
    participant Cache

    %% Viewing Todos
    User->>Browser: Navigate to Todos
    Browser->>App: GET /todos/todo-page
    App->>App: Verify Authentication
    App->>Cache: Check cache

    alt Cache Miss
        App->>DB: Fallback to DB query
        App->>Cache: Store in Cache
    end

    App->>Browser: Return todos

    %% Adding a Todo
    User->>Browser: Click "Add Todo"
    Browser->>App: GET /todos/add-todo-page
    App->>Browser: Render form
    User->>Browser: Fill Todo Form
    Browser->>App: Submit data
    App->>App: Sanitize input
    App->>DB: Save to DB
    App->>Cache: Invalidate cache
    App->>App: Log action
    App->>Browser: Redirect to Todos Page

    %% Editing a Todo
    User->>Browser: Click "Edit" on Todo
    Browser->>App: GET /todos/edit-todo-page/{id}
    App->>DB: Fetch existing data
    App->>Browser: Return Edit Form
    User->>Browser: Update Todo
    Browser->>App: PUT /todos/{id}
    App->>App: Sanitize input
    App->>DB: Update after sanitizing
    App->>Cache: Invalidate cache
    App->>App: Log
    App->>Browser: Redirect to Todos Page

    %% Deleting a Todo
    User->>Browser: Click "Delete" on Todo
    Browser->>App: DELETE /todos/{id}
    App->>DB: Delete from DB
    App->>Cache: Invalidate cache
    App->>App: Log action
    App->>Browser: Return Success
```

## Admin Flow

```mermaid
sequenceDiagram
    participant Admin
    participant Browser
    participant App as SecureTodo App
    participant DB as Database

    %% Admin loads dashboard and gets user stats & logs
    Admin->>Browser: Navigate to Admin Dashboard
    Browser->>App: GET /admin/dashboard
    App->>App: Verify Admin Role
    Note right of App: Role verification before admin action
    App->>DB: Get User Statistics
    App->>DB: Get Activity Logs
    App->>Browser: Return Admin Dashboard

    %% Admin manages users (view)
    Admin->>Browser: Click "Manage Users"
    Browser->>App: GET /admin/users
    App->>App: Verify Admin Role
    Note right of App: Role verification before admin action
    App->>DB: Get All Users
    App->>Browser: Return User Management Page

    %% Admin manages users (edit)
    Admin->>Browser: Click "Edit" on User
    Browser->>App: GET /admin/users/{id}
    App->>App: Verify Admin Role
    Note right of App: Role verification before admin action
    App->>DB: Get User Details
    App->>Browser: Return Edit User Form
    Admin->>Browser: Update User Details
    Browser->>App: PUT /admin/users/{id}
    App->>App: Verify Admin Role
    Note right of App: Role verification before admin action
    App->>DB: Update User
    App->>App: Log Activity
    App->>Browser: Return Success

    %% Admin reviews activity logs
    Admin->>Browser: Click "Activity Logs"
    Browser->>App: GET /admin/activity-logs
    App->>App: Verify Admin Role
    Note right of App: Role verification before admin action
    App->>DB: Get Activity Logs
    App->>Browser: Return Activity Logs Page
```
