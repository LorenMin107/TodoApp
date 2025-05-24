from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from ..database import Base
from fastapi.testclient import TestClient
import pytest
from ..main import app
from ..models import Todos, Users
from ..routers.auth.token_manager import bcrypt_context

SQLALCHEMY_DATABASE_URI = 'sqlite:///./testdb.db'

# this engine is used for testing purposes only
engine = create_engine(
    SQLALCHEMY_DATABASE_URI,
    connect_args={
        'check_same_thread': False
    },
    poolclass=StaticPool
)

# This creates a new session for each request
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# This creates the database tables
Base.metadata.create_all(bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def override_get_current_user():
    return {"username": "lorenmin", "user_role": "admin", "id": 1}


client = TestClient(app)


@pytest.fixture
def test_todo():
    todo = Todos(
        title="Learn to code!",
        description="Learn to code with Python",
        priority=1,
        complete=False,
        owner_id=1
    )

    db = TestingSessionLocal()
    db.add(todo)
    db.commit()
    yield todo
    with engine.connect() as connection:
        connection.execute(text("DELETE FROM todos;"))
        connection.commit()


@pytest.fixture
def test_user():
    user = Users(
        username="lorenmin",
        email="lorenmin@gmail.com",
        first_name="Loren",
        last_name="Min",
        hashed_password=bcrypt_context.hash("test1234!"),
        role="admin",
        phone_number="1234567890"
    )
    db = TestingSessionLocal()
    db.add(user)
    db.commit()
    yield user
    with engine.connect() as connection:
        connection.execute(text("DELETE FROM users;"))
        connection.commit()
