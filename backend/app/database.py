# from sqlalchemy import create_engine
# from sqlalchemy.orm import DeclarativeBase, sessionmaker
# from .config import settings

# engine = create_engine(settings.database_url, pool_pre_ping=True)
# SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# class Base(DeclarativeBase):
#     pass

# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import settings


database_url = settings.database_url

# Render/PostgreSQL URLs normally start with postgresql://.
# Explicitly use psycopg 3 instead of the older psycopg2 driver.
if database_url.startswith("postgresql://"):
    database_url = database_url.replace(
        "postgresql://",
        "postgresql+psycopg://",
        1,
    )

engine = create_engine(
    database_url,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()