"""Async SQLAlchemy engine and session factory."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from typing import Any

from app.infrastructure.config.settings import Settings, get_settings

_settings = get_settings()


def build_engine_kwargs(settings: Settings) -> dict[str, Any]:
    """Build robust SQLAlchemy engine arguments for local and cloud PostgreSQL (Supabase/Render)."""
    url = settings.database_url
    connect_args: dict[str, Any] = {}

    _is_supabase = "supabase.co" in url or "supabase.com" in url
    _is_pooler = "pooler.supabase.com" in url or ":6543" in url

    # Supabase Transaction Pooler (port 6543) does not support prepared statements
    if _is_pooler:
        connect_args["statement_cache_size"] = 0
        connect_args["prepared_statement_cache_size"] = 0

    # Cloud databases require SSL — Supabase (all variants), Render, Neon, AWS RDS
    _cloud_hosts = [
        "supabase.co",
        "supabase.com",
        "onrender.com",
        "neon.tech",
        "rds.amazonaws.com",
    ]
    if any(host in url for host in _cloud_hosts) or "ssl=" in url:
        connect_args["ssl"] = "require"

    return {
        "pool_size": min(settings.database_pool_size, 5) if _is_supabase else min(settings.database_pool_size, 10),
        "max_overflow": min(settings.database_max_overflow, 5) if _is_supabase else min(settings.database_max_overflow, 10),
        "pool_pre_ping": True,  # Discard stale connections dropped by cloud NAT
        "pool_recycle": 300,    # Recycle connections every 5 minutes
        "echo": settings.database_echo,
        "future": True,
        "connect_args": connect_args,
    }


engine = create_async_engine(
    _settings.database_url,
    **build_engine_kwargs(_settings),
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async DB session per request.

    The session is automatically committed on success and rolled back
    on any exception, then closed in the finally block.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
