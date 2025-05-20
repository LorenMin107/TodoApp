from typing import Annotated
import logging
from sqlalchemy.exc import SQLAlchemyError
from jose.exceptions import JWTError

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException, Path, APIRouter, Request
from starlette import status
from ..models import Todos
from ..database import SessionLocal
from .auth import get_current_user, get_current_user_from_cookie
from starlette.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from ..sanitize import sanitize_todo_input, sanitize_html

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


def redirect_to_login():
    redirect_response = RedirectResponse(url="/auth/login-page", status_code=status.HTTP_302_FOUND)
    redirect_response.delete_cookie(key="access_token")
    return redirect_response


### Pages ####

@router.get("/todo-page")
async def render_todo_page(request: Request, db: db_dependency, user: user_dependency = None):
    try:
        if user is None:
            logger.info("User not authenticated, redirecting to login page")
            return redirect_to_login()

        todos = db.query(Todos).filter(Todos.owner_id == user.get('id')).all()
        return templates.TemplateResponse("todo.html", {"request": request, "todos": todos, "user": user})

    except JWTError as e:
        logger.error(f"JWT error in render_todo_page: {str(e)}")
        return redirect_to_login()
    except SQLAlchemyError as e:
        logger.error(f"Database error in render_todo_page: {str(e)}")
        return redirect_to_login()
    except AttributeError as e:
        logger.error(f"Attribute error in render_todo_page: {str(e)}")
        return redirect_to_login()
    except Exception as e:
        logger.error(f"Unexpected error in render_todo_page: {str(e)}")
        return redirect_to_login()


@router.get("/add-todo-page")
async def render_add_todo_page(request: Request, user: user_dependency = None):
    try:
        if user is None:
            logger.info("User not authenticated, redirecting to login page")
            return redirect_to_login()
        return templates.TemplateResponse("add-todo.html", {"request": request, "user": user})
    except JWTError as e:
        logger.error(f"JWT error in render_add_todo_page: {str(e)}")
        return redirect_to_login()
    except AttributeError as e:
        logger.error(f"Attribute error in render_add_todo_page: {str(e)}")
        return redirect_to_login()
    except Exception as e:
        logger.error(f"Unexpected error in render_add_todo_page: {str(e)}")
        return redirect_to_login()


@router.get("/edit-todo-page/{todo_id}")
async def render_edit_todo_page(request: Request, todo_id: int, db: db_dependency, user: user_dependency = None):
    try:
        if user is None:
            logger.info("User not authenticated, redirecting to login page")
            return redirect_to_login()

        todo = db.query(Todos).filter(Todos.id == todo_id).first()
        if todo is None:
            logger.warning(f"Todo with id {todo_id} not found")
            return RedirectResponse(url="/todos/todo-page", status_code=status.HTTP_302_FOUND)

        return templates.TemplateResponse("edit-todo.html", {"request": request, "todo": todo, "user": user})
    except JWTError as e:
        logger.error(f"JWT error in render_edit_todo_page: {str(e)}")
        return redirect_to_login()
    except SQLAlchemyError as e:
        logger.error(f"Database error in render_edit_todo_page: {str(e)}")
        return redirect_to_login()
    except AttributeError as e:
        logger.error(f"Attribute error in render_edit_todo_page: {str(e)}")
        return redirect_to_login()
    except Exception as e:
        logger.error(f"Unexpected error in render_edit_todo_page: {str(e)}")
        return redirect_to_login()


### Endpoints for rendering pages ####
@router.get("/", status_code=status.HTTP_200_OK)
async def read_all(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="User not authenticated.")
    return db.query(Todos).filter(Todos.owner_id == user.get('id')).all()


@router.get("/todo/{todo_id}", status_code=status.HTTP_200_OK)
async def read_todo(user: user_dependency, db: db_dependency, todo_id: int = Path(gt=0)):
    if user is None:
        raise HTTPException(status_code=401, detail="User not authenticated.")

    todo_model = db.query(Todos).filter(Todos.id == todo_id).filter(Todos.owner_id == user.get('id')).first()
    if todo_model is not None:
        return todo_model
    raise HTTPException(status_code=404, detail="Todo not found")


@router.post("/todo", status_code=status.HTTP_201_CREATED)
async def create_todo(user: user_dependency, db: db_dependency, todo_request: TodoRequest):
    if user is None:
        raise HTTPException(status_code=401, detail="User not authenticated.")

    # Sanitize user input to prevent XSS attacks
    sanitized_data = sanitize_todo_input(todo_request.model_dump())
    todo_model = Todos(**sanitized_data, owner_id=user.get('id'))

    db.add(todo_model)
    db.commit()


@router.put("/todo/{todo_id}", status_code=status.HTTP_204_NO_CONTENT)
async def update_todo(user: user_dependency, db: db_dependency, todo_request: TodoRequest, todo_id: int = Path(gt=0)):
    if user is None:
        raise HTTPException(status_code=401, detail="User not authenticated.")
    todo_model = db.query(Todos).filter(Todos.id == todo_id).filter(Todos.owner_id == user.get('id')).first()
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


@router.delete("/todo/{todo_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_todo(user: user_dependency, db: db_dependency, todo_id: int = Path(gt=0)):
    if user is None:
        raise HTTPException(status_code=401, detail="User not authenticated.")
    todo_model = db.query(Todos).filter(Todos.id == todo_id).filter(Todos.owner_id == user.get('id')).first()
    if todo_model is None:
        raise HTTPException(status_code=404, detail="Todo not found.")
    db.query(Todos).filter(Todos.id == todo_id).filter(Todos.owner_id == user.get('id')).delete()

    db.commit()
