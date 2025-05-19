from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import DeclarativeBase

# This is the database URI that will be used to connect to the database
SQLALCHEMY_DATABASE_URI = 'sqlite:///todosapp.db'

# SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:test1234!@localhost/TodoApplicationDatabase'
# SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:test1234!@127.0.0.1/TodoApplicationDatabase'

# This is the database engine that will be used to connect to the database (remove connect_args for PostgreSQL and MySQL)
engine = create_engine(SQLALCHEMY_DATABASE_URI, connect_args={
    'check_same_thread': False})

# This creates a new session for each request
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
class Base(DeclarativeBase):
    pass
