from typing import Annotated, List, Optional
from datetime import datetime
from pydantic import BaseModel

from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException, Path, APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette import status
from ..models import Todos, Users, ActivityLog
from ..database import SessionLocal
from .auth.token_manager import get_current_user_from_cookie
from ..activity_logger import log_activity

router = APIRouter(
    prefix="/admin",
    tags=["admin"]
)

# Templates for rendering pages
templates = Jinja2Templates(directory="TodoApp/templates")

# Request models
class UserRoleUpdate(BaseModel):
    role: str

class UserStatusUpdate(BaseModel):
    is_active: bool

class ActivityLogSchema(BaseModel):
    timestamp: datetime
    username: str
    action: str
    details: str

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


# Admin dashboard
@router.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard(request: Request, user: user_dependency, db: db_dependency):
    if user is None or user.get('user_role') != 'admin':
        raise HTTPException(status_code=401, detail="Unauthorized. Admin access required.")

    # Get all users
    users = db.query(Users).all()

    # Get all todos with owner information
    todos_with_owners = []
    todos = db.query(Todos).all()
    for todo in todos:
        owner = db.query(Users).filter(Users.id == todo.owner_id).first()
        owner_username = owner.username if owner else "Unknown"
        todo_dict = {
            "id": todo.id,
            "title": todo.title,
            "description": todo.description,
            "priority": todo.priority,
            "complete": todo.complete,
            "owner_id": todo.owner_id,
            "owner_username": owner_username
        }
        todos_with_owners.append(todo_dict)

    # Get recent activities
    activities = db.query(ActivityLog).order_by(ActivityLog.timestamp.desc()).limit(100).all()

    # Log the dashboard access
    log_activity(
        db=db,
        user_id=user.get('id'),
        username=user.get('username'),
        action="view_admin_dashboard",
        details="Accessed the admin dashboard"
    )

    return templates.TemplateResponse(
        "admin-dashboard.html", 
        {
            "request": request, 
            "user": user,
            "users": users,
            "todos": todos_with_owners,
            "activities": activities
        }
    )

# User management endpoints
@router.get("/users", status_code=status.HTTP_200_OK)
async def get_all_users(user: user_dependency, db: db_dependency):
    if user is None or user.get('user_role') != 'admin':
        raise HTTPException(status_code=401, detail="Unauthorized. Admin access required.")

    users = db.query(Users).all()
    return users

@router.put("/users/{user_id}/role", status_code=status.HTTP_200_OK)
async def update_user_role(
    user: user_dependency, 
    db: db_dependency, 
    user_id: int = Path(gt=0), 
    role_update: UserRoleUpdate = None
):
    if user is None or user.get('user_role') != 'admin':
        raise HTTPException(status_code=401, detail="Unauthorized. Admin access required.")

    if role_update is None or role_update.role not in ['user', 'admin']:
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'user' or 'admin'.")

    user_to_update = db.query(Users).filter(Users.id == user_id).first()
    if user_to_update is None:
        raise HTTPException(status_code=404, detail="User not found")

    user_to_update.role = role_update.role
    db.add(user_to_update)
    db.commit()

    # Log the activity
    log_activity(
        db=db,
        user_id=user.get('id'),
        username=user.get('username'),
        action="update_user_role",
        details=f"Updated user {user_to_update.username} (ID: {user_id}) role to {role_update.role}"
    )

    return {"message": f"User {user_id} role updated to {role_update.role}"}

@router.put("/users/{user_id}/status", status_code=status.HTTP_200_OK)
async def update_user_status(
    user: user_dependency, 
    db: db_dependency, 
    user_id: int = Path(gt=0), 
    status_update: UserStatusUpdate = None
):
    if user is None or user.get('user_role') != 'admin':
        raise HTTPException(status_code=401, detail="Unauthorized. Admin access required.")

    if status_update is None:
        raise HTTPException(status_code=400, detail="Invalid status update")

    user_to_update = db.query(Users).filter(Users.id == user_id).first()
    if user_to_update is None:
        raise HTTPException(status_code=404, detail="User not found")

    user_to_update.is_active = status_update.is_active
    db.add(user_to_update)
    db.commit()

    status_str = "activated" if status_update.is_active else "deactivated"

    # Log the activity
    log_activity(
        db=db,
        user_id=user.get('id'),
        username=user.get('username'),
        action="update_user_status",
        details=f"User {user_to_update.username} (ID: {user_id}) {status_str}"
    )

    return {"message": f"User {user_id} {status_str}"}

# Todo management endpoints
@router.get("/todo", status_code=status.HTTP_200_OK)
async def read_all_todos(user: user_dependency, db: db_dependency):
    if user is None or user.get('user_role') != 'admin':
        raise HTTPException(status_code=401, detail="Unauthorized. Admin access required.")
    return db.query(Todos).all()

@router.delete("/todo/{todo_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_todo(user: user_dependency, db: db_dependency, todo_id: int = Path(gt=0)):
    if user is None or user.get('user_role') != 'admin':
        raise HTTPException(status_code=401, detail="Unauthorized. Admin access required.")
    todo_model = db.query(Todos).filter(Todos.id == todo_id).first()
    if todo_model is None:
        raise HTTPException(status_code=404, detail="Todo not found")

    # Get the owner of the todo for logging
    owner = db.query(Users).filter(Users.id == todo_model.owner_id).first()
    owner_username = owner.username if owner else "Unknown"

    # Store todo details for logging before deletion
    todo_title = todo_model.title

    # Delete the todo
    db.query(Todos).filter(Todos.id == todo_id).delete()
    db.commit()

    # Log the activity
    log_activity(
        db=db,
        user_id=user.get('id'),
        username=user.get('username'),
        action="delete_todo",
        details=f"Deleted todo '{todo_title}' (ID: {todo_id}) owned by {owner_username}"
    )
