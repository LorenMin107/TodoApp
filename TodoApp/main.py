from fastapi import FastAPI, Request, status, Cookie
from .models import Base
from .database import engine

from .routers import auth, todos, admin, users
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from .csrf import csrf_middleware
from .csp import CSPMiddleware
from jose import JWTError
from typing import Optional


app = FastAPI()

# Add CSP middleware
app.add_middleware(CSPMiddleware)

# Add CSRF middleware
app.middleware("http")(csrf_middleware)

Base.metadata.create_all(bind=engine)

app.mount("/static", StaticFiles(directory="TodoApp/static"), name="static")


@app.get("/")
async def root(request: Request, access_token: Optional[str] = Cookie(None)):
    # If no access token is present, redirect to the login page
    if access_token is None:
        return RedirectResponse(url="/auth/login-page", status_code=status.HTTP_302_FOUND)

    # Try to validate the token
    try:
        # Import here to avoid circular imports
        from .routers.auth import SECRET_KEY, ALGORITHM, jwt

        # Decode the JWT token
        jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])

        return RedirectResponse(url="/todos/todo-page", status_code=status.HTTP_302_FOUND)
    except JWTError:
        # If the token is invalid, redirect to the login page and clear the cookie
        response = RedirectResponse(url="/auth/login-page", status_code=status.HTTP_302_FOUND)
        response.delete_cookie(key="access_token")
        return response


@app.get("/healthy")
def health_check():
    return {"status": "healthy"}


app.include_router(auth.router)
app.include_router(todos.router)
app.include_router(admin.router)
app.include_router(users.router)
