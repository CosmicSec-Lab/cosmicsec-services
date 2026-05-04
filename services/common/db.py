"""Shared SQLAlchemy engine/session configuration with pooling.

Phase S.2 — Read-replica support:
  - Primary engine (write) bound to DATABASE_URL
  - Read-replica engine bound to COSMICSEC_DB_READ_URL (falls back to primary)
  - Use `get_read_db()` for SELECT-only queries to route to replica
  - EXPLAIN ANALYZE logging for slow queries (>100ms) when COSMICSEC_SLOW_QUERY_MS is set
"""

import logging
import os
import time
from threading import Lock

from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./cosmicsec.db",
)

# Optional read-replica URL — falls back to primary if not set
_READ_URL = os.getenv("COSMICSEC_DB_READ_URL", DATABASE_URL)

# Threshold for slow-query logging (milliseconds); 0 = disabled
_SLOW_QUERY_MS = int(os.getenv("COSMICSEC_SLOW_QUERY_MS", "100"))


def _build_engine(url: str, *, read_only: bool = False):
    kwargs = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs["pool_size"] = 5 if read_only else 10
        kwargs["max_overflow"] = 10 if read_only else 20
        if read_only:
            kwargs["pool_timeout"] = 20
    eng = create_engine(url, **kwargs)

    if _SLOW_QUERY_MS > 0 and not url.startswith("sqlite"):

        @event.listens_for(eng, "before_cursor_execute")
        def _before(conn, cursor, statement, parameters, context, executemany):
            context._query_start_time = time.monotonic()

        @event.listens_for(eng, "after_cursor_execute")
        def _after(conn, cursor, statement, parameters, context, executemany):
            elapsed_ms = (time.monotonic() - context._query_start_time) * 1000
            if elapsed_ms > _SLOW_QUERY_MS:
                logger.warning(
                    "Slow query (%.1f ms): %s",
                    elapsed_ms,
                    statement[:200],
                )

    return eng


engine = _build_engine(DATABASE_URL)
_read_engine = _build_engine(_READ_URL, read_only=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
ReadSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_read_engine)
Base = declarative_base()
_sqlite_schema_ready = False
_sqlite_schema_lock = Lock()


def _ensure_sqlite_schema() -> None:
    """Create tables lazily for SQLite-only dev/test environments."""
    global _sqlite_schema_ready
    if _sqlite_schema_ready:
        return
    if not DATABASE_URL.startswith("sqlite"):
        _sqlite_schema_ready = True
        return

    with _sqlite_schema_lock:
        if _sqlite_schema_ready:
            return
        # Import model metadata lazily to avoid circular imports at module load time.
        from services.common import models  # noqa: F401

        Base.metadata.create_all(bind=engine)
        _sqlite_schema_ready = True


def get_db():
    """Yield a write-capable DB session (routes to primary)."""
    _ensure_sqlite_schema()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_read_db():
    """Yield a read-only DB session (routes to replica when configured)."""
    _ensure_sqlite_schema()
    db = ReadSessionLocal()
    try:
        yield db
    finally:
        db.close()
