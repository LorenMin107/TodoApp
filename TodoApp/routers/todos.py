from typing import Annotated, Callable, TypeVar, Any, List
import logging
import functools
from sqlalchemy.exc import SQLAlchemyError
from jose.exceptions import JWTError

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException, Path, APIRouter, Request
from starlette import status
from ..models import Todos
from ..database import SessionLocal
from .auth.token_manager import get_current_user_from_cookie
from .auth.two_factor import check_pending_2fa_session
from starlette.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from ..sanitize import sanitize_todo_input
from ..cache import cached, async_cached, cache_invalidate_pattern

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

templates = Jinja2Templates(directory="TodoApp/templates")
router = APIRouter(
    prefix="/todos",
    tags=["todos"]
)


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


# This is the request model that will be used to create a new todo item
class TodoRequest(BaseModel):
    title: str = Field(min_length=3)
    description: str = Field(min_length=3, max_length=100)
    priority: int = Field(gt=0, lt=6)
    complete: bool


def redirect_to_login(request: Request = None):
    # Check if there's a pending 2FA session
    if request:
        has_2fa_session, _ = check_pending_2fa_session(request)
        if has_2fa_session:
            # Redirect to 2FA verification page instead of login page
            return RedirectResponse(url="/auth/verify-2fa-page", status_code=status.HTTP_302_FOUND)

    # No 2FA session, redirect to login page
    redirect_response = RedirectResponse(url="/auth/login-page", status_code=status.HTTP_302_FOUND)
    redirect_response.delete_cookie(key="access_token")
    return redirect_response


# Type variable for the decorator
T = TypeVar('T')


def handle_exceptions(func: Callable[..., T]) -> Callable[..., T]:
    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> T:
        try:
            return await func(*args, **kwargs)
        except JWTError as e:
            logger.error(f"JWT error in {func.__name__}: {str(e)}")
            # Get the request object from kwargs
            request = kwargs.get('request')
            return redirect_to_login(request)
        except SQLAlchemyError as e:
            logger.error(f"Database error in {func.__name__}: {str(e)}")
            request = kwargs.get('request')
            return redirect_to_login(request)
        except AttributeError as e:
            logger.error(f"Attribute error in {func.__name__}: {str(e)}")
            request = kwargs.get('request')
            return redirect_to_login(request)
        except Exception as e:
            logger.error(f"Unexpected error in {func.__name__}: {str(e)}")
            request = kwargs.get('request')
            return redirect_to_login(request)

    return wrapper


def require_auth(func: Callable[..., T]) -> Callable[..., T]:
    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> T:
        # Get the user and request objects from kwargs
        user = kwargs.get('user')
        request = kwargs.get('request')

        if user is None:
            logger.info(f"User not authenticated, redirecting to login page in {func.__name__}")
            return redirect_to_login(request)

        return await func(*args, **kwargs)

    return wrapper


### Pages ####

@router.get("/todo-page")
@handle_exceptions
@require_auth
async def render_todo_page(request: Request, db: db_dependency, user: user_dependency = None):
    todos = get_all_todos_for_user(db, user.get('id'))
    return templates.TemplateResponse("todo.html", {"request": request, "todos": todos, "user": user})


@router.get("/add-todo-page")
@handle_exceptions
@require_auth
async def render_add_todo_page(request: Request, user: user_dependency = None):
    return templates.TemplateResponse("add-todo.html", {"request": request, "user": user})


@router.get("/edit-todo-page/{todo_id}")
@handle_exceptions
@require_auth
async def render_edit_todo_page(request: Request, todo_id: int, db: db_dependency, user: user_dependency = None):
    # Use get_todo_by_id_and_owner to ensure the user can only edit their own todos
    todo = get_todo_by_id_and_owner(db, todo_id, user.get('id'))
    if todo is None:
        logger.warning(f"Todo with id {todo_id} not found or does not belong to user {user.get('id')}")
        return RedirectResponse(url="/todos/todo-page", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse("edit-todo.html", {"request": request, "todo": todo, "user": user})


### Database query utility functions ###
@cached(key_prefix="todos", ttl=60)  # Cache for 1 minute
def get_all_todos_for_user(db: Session, user_id: int) -> List[Todos]:
    """
    Get all todos for a user.

    Args:
        db: The database session
        user_id: The ID of the user

    Returns:
        A list of todos belonging to the user
    """
    return db.query(Todos).filter(Todos.owner_id == user_id).all()


@cached(key_prefix="todo", ttl=60)  # Cache for 1 minute
def get_todo_by_id_and_owner(db: Session, todo_id: int, owner_id: int) -> Todos:
    """
    Get a todo by ID and owner ID.

    Args:
        db: The database session
        todo_id: The ID of the todo
        owner_id: The ID of the owner

    Returns:
        The todo if found, None otherwise
    """
    return db.query(Todos).filter(Todos.id == todo_id).filter(Todos.owner_id == owner_id).first()


# This function should only be used in admin contexts or when owner verification is done separately
def get_todo_by_id(db: Session, todo_id: int) -> Todos:
    """
    Get a todo by ID without checking ownership.

    WARNING: This function should only be used in admin contexts or when owner verification
    is done separately to avoid security issues.

    Args:
        db: The database session
        todo_id: The ID of the todo

    Returns:
        The todo if found, None otherwise
    """
    return db.query(Todos).filter(Todos.id == todo_id).first()


### Endpoints for rendering pages ####
@router.get("/", status_code=status.HTTP_200_OK)
@require_auth
async def read_all(user: user_dependency, db: db_dependency):
    return get_all_todos_for_user(db, user.get('id'))


@router.get("/todo/{todo_id}", status_code=status.HTTP_200_OK)
@require_auth
async def read_todo(user: user_dependency, db: db_dependency, todo_id: int = Path(gt=0)):
    todo_model = get_todo_by_id_and_owner(db, todo_id, user.get('id'))
    if todo_model is not None:
        return todo_model
    raise HTTPException(status_code=404, detail="Todo not found")


@router.post("/todo", status_code=status.HTTP_201_CREATED)
@require_auth
async def create_todo(user: user_dependency, db: db_dependency, todo_request: TodoRequest):
    # Sanitize user input to prevent XSS attacks
    sanitized_data = sanitize_todo_input(todo_request.model_dump())
    todo_model = Todos(**sanitized_data, owner_id=user.get('id'))

    db.add(todo_model)
    db.commit()

    # Invalidate cache for this user's todos
    cache_invalidate_pattern(f"todos:get_all_todos_for_user:{user.get('id')}")


@router.put("/todo/{todo_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_auth
async def update_todo(user: user_dependency, db: db_dependency, todo_request: TodoRequest, todo_id: int = Path(gt=0)):
    todo_model = get_todo_by_id_and_owner(db, todo_id, user.get('id'))
    if todo_model is None:
        raise HTTPException(status_code=404, detail="Todo not found.")

    # Sanitize user input to prevent XSS attacks
    sanitized_data = sanitize_todo_input(todo_request.model_dump())

    todo_model.title = sanitized_data['title']
    todo_model.description = sanitized_data['description']
    todo_model.priority = todo_request.priority
    todo_model.complete = todo_request.complete

    db.add(todo_model)
    db.commit()

    # Invalidate cache for this user's todos and this specific todo
    user_id = user.get('id')
    cache_invalidate_pattern(f"todos:get_all_todos_for_user:{user_id}")
    cache_invalidate_pattern(f"todo:get_todo_by_id_and_owner:{todo_id}:{user_id}")


@router.delete("/todo/{todo_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_auth
async def delete_todo(user: user_dependency, db: db_dependency, todo_id: int = Path(gt=0)):
    todo_model = get_todo_by_id_and_owner(db, todo_id, user.get('id'))
    if todo_model is None:
        raise HTTPException(status_code=404, detail="Todo not found.")

    # Delete the todo - use the model directly instead of querying again
    db.delete(todo_model)
    db.commit()

    # Invalidate cache for this user's todos and this specific todo
    user_id = user.get('id')
    cache_invalidate_pattern(f"todos:get_all_todos_for_user:{user_id}")
    cache_invalidate_pattern(f"todo:get_todo_by_id_and_owner:{todo_id}:{user_id}")
