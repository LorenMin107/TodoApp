from fastapi import FastAPI, Request, status, Cookie
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from typing import Optional
from jose import JWTError
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Internal modules
from .models import Base
from .database import engine, SessionLocal
from .routers.auth import router as auth_router
from .routers import todos, admin, users
from .csrf import csrf_middleware
from .csp import CSPMiddleware
from .admin_init import initialize_admin_user

app = FastAPI()

# Add CSP middleware
app.add_middleware(CSPMiddleware)

# Add CSRF middleware
app.middleware("http")(csrf_middleware)

# Create database tables if they don't exist
Base.metadata.create_all(bind=engine)

# Initialize admin user
with SessionLocal() as db:
    initialize_admin_user(db)

app.mount("/static", StaticFiles(directory="TodoApp/static"), name="static")


@app.get("/")
async def root(request: Request, access_token: Optional[str] = Cookie(None)):
    # If no access token is present, redirect to the login page
    if access_token is None:
        return RedirectResponse(url="/auth/login-page", status_code=status.HTTP_302_FOUND)

    # Try to validate the token
    try:
        # Import here to avoid circular imports
        from .routers.auth.token_manager import SECRET_KEY, ALGORITHM
        from jose import jwt

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


app.include_router(auth_router)
app.include_router(todos.router)
app.include_router(admin.router)
app.include_router(users.router)

# Run app with `python3 -m TodoApp.main`
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("TodoApp.main:app", host="localhost", port=8000, reload=True)
