from typing import Annotated

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException, APIRouter, Request
from starlette import status
from starlette.responses import RedirectResponse
from ..models import Users
from ..database import SessionLocal
from .auth.token_manager import get_current_user_from_cookie, verify_password, hash_password
from ..password_validator import validate_password
from ..sanitize import sanitize_html
from ..cache import cache_invalidate_pattern
from fastapi.templating import Jinja2Templates

router = APIRouter(
    prefix="/user",
    tags=["user"]
)

templates = Jinja2Templates(directory="TodoApp/templates")


# This is the database engine that will be used to connect to the database
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# This is the dependency that will be used to get the database session
db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user_from_cookie)]


class UserVerification(BaseModel):
    password: str
    new_password: str = Field(min_length=6)


@router.get('/', status_code=status.HTTP_200_OK)
async def get_user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="User not authenticated.")
    return db.query(Users).filter(Users.id == user.get('id')).first()


@router.put('/password', status_code=status.HTTP_204_NO_CONTENT)
async def change_password(user: user_dependency, db: db_dependency, user_verification: UserVerification):
    if user is None:
        raise HTTPException(status_code=401, detail="User not authenticated.")
    user_model = db.query(Users).filter(Users.id == user.get('id')).first()

    if not verify_password(user_verification.password, user_model.hashed_password):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    # Validate new password strength
    is_valid, error_message = validate_password(user_verification.new_password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message
        )

    user_model.hashed_password = hash_password(user_verification.new_password)
    db.add(user_model)
    db.commit()

    # Invalidate cache for this user
    cache_invalidate_pattern(f"auth:get_user_by_username:{user_model.username}")


@router.put('/phonenumber/{phone_number}', status_code=status.HTTP_204_NO_CONTENT)
async def change_phone_number(user: user_dependency, db: db_dependency, phone_number: str):
    if user is None:
        raise HTTPException(status_code=401, detail="User not authenticated.")
    user_model = db.query(Users).filter(Users.id == user.get('id')).first()
    # Sanitize phone_number to prevent XSS attacks
    sanitized_phone_number = sanitize_html(phone_number)
    user_model.phone_number = sanitized_phone_number
    db.add(user_model)
    db.commit()

    # Invalidate cache for this user
    cache_invalidate_pattern(f"auth:get_user_by_username:{user_model.username}")


@router.get('/profile')
async def profile_page(request: Request, user: user_dependency, db: db_dependency):
    if user is None:
        return RedirectResponse(url="/auth/login-page", status_code=status.HTTP_303_SEE_OTHER)

    # Get the user from the database
    db_user = db.query(Users).filter(Users.id == user.get('id')).first()
    if not db_user:
        return RedirectResponse(url="/auth/login-page", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse(
        "profile.html", 
        {
            "request": request, 
            "user": user,
            "db_user": db_user,
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success")
        }
    )
