from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import QueuePool
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database configuration from environment variables
DB_NAME = os.environ.get('DB_NAME', 'todosapp.db')

# Using SQLite as the only database type
SQLALCHEMY_DATABASE_URI = f'sqlite:///{DB_NAME}'

# Configure connection pooling parameters
POOL_SIZE = 5  # Default number of connections to keep open
MAX_OVERFLOW = 10  # Maximum number of connections to create the above pool_size
POOL_TIMEOUT = 30  # Timeout for getting a connection from the pool
POOL_RECYCLE = 1800  # Recycle connections after 30 minutes

connect_args = {'check_same_thread': False} if SQLALCHEMY_DATABASE_URI.startswith('sqlite') else {}

# Create an engine with connection pooling
engine = create_engine(
    SQLALCHEMY_DATABASE_URI,
    poolclass=QueuePool,
    pool_size=POOL_SIZE,
    max_overflow=MAX_OVERFLOW,
    pool_timeout=POOL_TIMEOUT,
    pool_recycle=POOL_RECYCLE,
    connect_args=connect_args
)

# This creates a new session for each request
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
class Base(DeclarativeBase):
    pass
