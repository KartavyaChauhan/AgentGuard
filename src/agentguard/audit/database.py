import sqlite3
from contextlib import contextmanager
from typing import Generator

class AuditPersistenceError(Exception):
    """Raised when an audit persistence operation fails."""
    pass

class AuditChainError(AuditPersistenceError):
    """Raised when an append operation would break the hash chain."""
    pass

def get_connection(db_path: str) -> sqlite3.Connection:
    """Get a new SQLite connection."""
    try:
        # uri=True allows for file:memory?cache=shared or similar if needed
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Enable write-ahead logging for better concurrency
        conn.execute("PRAGMA journal_mode=WAL")
        return conn
    except sqlite3.Error as e:
        raise AuditPersistenceError(f"Failed to connect to SQLite: {e}") from e

@contextmanager
def get_managed_connection(db_path: str) -> Generator[sqlite3.Connection, None, None]:
    """Get a connection that automatically closes when the context manager exits."""
    conn = get_connection(db_path)
    try:
        yield conn
    finally:
        conn.close()

@contextmanager
def transaction(conn: sqlite3.Connection) -> Generator[sqlite3.Cursor, None, None]:
    """Context manager for SQLite transactions."""
    cursor = conn.cursor()
    try:
        yield cursor
        conn.commit()
    except Exception as e:
        conn.rollback()
        if isinstance(e, AuditPersistenceError):
            raise
        raise AuditPersistenceError(f"Transaction failed: {e}") from e
    finally:
        cursor.close()
