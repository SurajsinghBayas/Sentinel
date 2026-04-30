"""
Database engine & session factory — async SQLAlchemy + Neon PostgreSQL
ANBU Sentinel
"""
import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from dotenv import load_dotenv

load_dotenv()

# Neon uses ?sslmode=require — asyncpg needs the equivalent driver URL
_raw_url = os.getenv("DATABASE_URL", "")

# Convert to asyncpg driver format and strip ALL query params
# (asyncpg SSL is configured via connect_args, not URL params)
_base_url = _raw_url.split("?")[0]  # drop ?sslmode=... etc.
DATABASE_URL = (
    _base_url
    .replace("postgresql://", "postgresql+asyncpg://")
    .replace("postgres://",    "postgresql+asyncpg://")
)

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_size=5,
    max_overflow=10,
    connect_args={"ssl": "require"},
)

AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db():
    """FastAPI dependency — yields an async DB session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Create all tables on startup."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
