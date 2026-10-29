"""SQLAlchemy declarative base."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for all SQLAlchemy ORM models.

    All models must inherit from this class and live in
    app/infrastructure/db/models/ so Alembic can discover them.
    """

    pass
