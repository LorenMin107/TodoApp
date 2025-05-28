# SecureTodo Application Flowchart

This document contains flowcharts representing the architecture and flow of the SecureTodo application.

## Application Architecture

The SecureTodo application architecture is divided into several logical components:

### Client and Middleware Layer

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
```

### Router Layer

```mermaid
graph TD
    %% Router Layer
    FastAPI[FastAPI Application] --> AuthRouter[Auth Router]
    FastAPI --> TodosRouter[Todos Router]
    FastAPI --> AdminRouter[Admin Router]
    FastAPI --> UsersRouter[Users Router]
```

### Authentication Components

```mermaid
graph TD
    %% Auth Components
    AuthRouter[Auth Router] --> Login[Login Module]
    AuthRouter --> Registration[Registration Module]
    AuthRouter --> PasswordReset[Password Reset Module]
    AuthRouter --> TwoFactor[Two-Factor Auth Module]
    AuthRouter --> TokenManager[Token Manager]

    %% Security Components
    Login --> PasswordValidator[Password Validator]
    Registration --> PasswordValidator
    PasswordReset --> PasswordValidator
    Login --> RateLimiter[Rate Limiter]
    Registration --> RateLimiter

    %% Email Integration
    PasswordReset --> EmailUtils[Email Utilities]
    Registration --> EmailUtils
```

### Database Layer

```mermaid
graph TD
    %% Database Layer
    TodosRouter[Todos Router] --> |CRUD Operations| Database[(Database)]
    AuthRouter[Auth Router] --> |User Operations| Database
    AdminRouter[Admin Router] --> |Admin Operations| Database
    UsersRouter[Users Router] --> |User Management| Database

    Database --> Users[Users Model]
    Database --> Todos[Todos Model]
    Database --> ActivityLog[Activity Log Model]
    Database --> RevokedTokens[Revoked Tokens Model]
```

### Utilities Layer

```mermaid
graph TD
    %% Utilities
    TodosRouter[Todos Router] --> ActivityLogger[Activity Logger]
    AuthRouter[Auth Router] --> ActivityLogger
    AdminRouter[Admin Router] --> ActivityLogger
    UsersRouter[Users Router] --> ActivityLogger

    TodosRouter --> Cache[Cache]
```

## Registration Process

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant App as SecureTodo App
    participant DB as Database

    User->>Browser: Opens register page
    Browser->>App: GET /auth/register-page
    App->>Browser: Return Registration Form
    User->>Browser: Submits form
    Browser->>App: POST /auth/register
    App->>App: Validates, hashes password, generates token
    App->>DB: Stores in DB
    App->>User: Sends email
    User->>Browser: Clicks verification link
    Browser->>App: GET /auth/verify-email?token=xyz
    App->>App: Verifies token
    App->>Browser: Redirects to login
```

## Login Flow

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant App as SecureTodo App
    participant DB as Database

    User->>Browser: Submits credentials
    Browser->>App: POST /auth/login
    App->>DB: Checks DB

    alt 2FA is enabled
        App->>Browser: Redirect to 2FA input
        User->>Browser: Enters 2FA code
        Browser->>App: POST /auth/verify-2fa
        App->>App: Verifies
    end

    App->>App: Issues JWT, sets cookie
    App->>Browser: Redirect to todos
```

## Password Reset Flow

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant App as SecureTodo App
    participant DB as Database

    User->>Browser: Requests reset
    Browser->>App: POST /auth/request-password-reset
    App->>App: Generates token
    App->>DB: Stores in DB
    App->>User: Sends reset link via email
    User->>Browser: Opens reset form
    Browser->>App: GET /auth/reset-password/{token}
    App->>Browser: Return password form
    User->>Browser: Submits new password
    Browser->>App: POST /auth/reset-password
    App->>App: Hashes and updates DB
    App->>Browser: Redirect to login
```

## Viewing Todos

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant App as SecureTodo App
    participant DB as Database
    participant Cache

    App->>Cache: Checks cache

    alt On miss
        App->>DB: Queries DB
        App->>Cache: Caches result
    end

    App->>Browser: Returns todos to browser
```

## Adding a Todo

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant App as SecureTodo App
    participant DB as Database
    participant Cache

    User->>Browser: Submits form
    Browser->>App: POST /todos
    App->>App: Sanitizes input
    App->>DB: Stores in DB
    App->>Cache: Invalidates cache
    App->>App: Logs action
    App->>Browser: Redirects user
```

## Editing a Todo

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant App as SecureTodo App
    participant DB as Database
    participant Cache

    User->>Browser: Loads form, updates data
    Browser->>App: PUT /todos/{id}
    App->>App: Sanitizes input
    App->>DB: Updates DB
    App->>Cache: Invalidates cache
    App->>App: Logs action
```

## Deleting a Todo

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant App as SecureTodo App
    participant DB as Database
    participant Cache

    User->>Browser: Clicks delete
    Browser->>App: DELETE /todos/{id}
    App->>DB: Deletes from DB
    App->>Cache: Invalidates cache
    App->>App: Logs action
    App->>Browser: Returns success
```

## Admin Dashboard Load

```mermaid
sequenceDiagram
    participant Admin
    participant Browser
    participant App as SecureTodo App
    participant DB as Database

    Admin->>Browser: Accesses dashboard
    Browser->>App: GET /admin/dashboard
    App->>App: Verifies role
    App->>DB: Fetches stats + logs from DB
    App->>Browser: Returns dashboard
```

## Admin Managing Users

```mermaid
sequenceDiagram
    participant Admin
    participant Browser
    participant App as SecureTodo App
    participant DB as Database

    Admin->>Browser: Views all users
    Browser->>App: GET /admin/users
    App->>App: Verifies role
    App->>DB: Fetches users
    App->>Browser: Returns user list

    Admin->>Browser: Edits one
    Browser->>App: PUT /admin/users/{id}
    App->>App: Verifies role
    App->>DB: Updates DB
    App->>App: Logs activity
    App->>Browser: Returns success
```

## Admin Viewing Activity Logs

```mermaid
sequenceDiagram
    participant Admin
    participant Browser
    participant App as SecureTodo App
    participant DB as Database

    Admin->>Browser: Accesses log page
    Browser->>App: GET /admin/activity-logs
    App->>App: Verifies role
    App->>DB: Fetches logs from DB
    App->>Browser: Returns log page
```
