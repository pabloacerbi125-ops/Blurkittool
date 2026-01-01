"""Migrate data from the local SQLite DB to a PostgreSQL database (Render).

Usage (recommended):
  1) Copy Render *External Database URL*.
  2) Run locally from /web:
     set DATABASE_URL=<EXTERNAL_DATABASE_URL>
     python migrate_sqlite_to_postgres.py --sqlite instance/blurkit.db

Notes:
- This expects an EMPTY Postgres database.
- It preserves IDs so relationships (mods.created_by, reglas.modalidad_id) stay intact.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


DATETIME_COLS = {
    "created_at",
    "updated_at",
    "last_login",
    "last_attempt",
    "blocked_until",
    "twofa_confirmed_at",
}


_BOOL_COLS_CACHE: dict[str, set[str]] = {}


def _normalize_database_url(url: str) -> str:
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql://", 1)
    return url


def _parse_dt(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        # Very old sqlite rows might store epoch
        try:
            return datetime.fromtimestamp(float(value))
        except Exception:
            return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        # Common sqlite formats
        try:
            return datetime.fromisoformat(s.replace("Z", ""))
        except Exception:
            pass
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt)
            except Exception:
                continue
    return value


def _sqlite_tables(conn: sqlite3.Connection) -> set[str]:
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return {row[0] for row in cur.fetchall()}


def _sqlite_rows(conn: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    conn.row_factory = sqlite3.Row
    cur = conn.execute(f"SELECT * FROM {table}")
    rows = [dict(r) for r in cur.fetchall()]
    return rows


def _coerce_row(row: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in row.items():
        if k in DATETIME_COLS:
            out[k] = _parse_dt(v)
        else:
            out[k] = v
    return out


def _dest_bool_columns(db, table: str) -> set[str]:
    """Return BOOLEAN column names for the destination table (Postgres).

    SQLite often stores booleans as 0/1 integers, which Postgres rejects when
    binding to BOOLEAN columns.
    """
    if table in _BOOL_COLS_CACHE:
        return _BOOL_COLS_CACHE[table]

    try:
        from sqlalchemy import inspect
        from sqlalchemy.sql.sqltypes import Boolean

        insp = inspect(db.engine)
        cols = insp.get_columns(table)
        bool_cols: set[str] = set()
        for c in cols:
            t = c.get("type")
            if isinstance(t, Boolean) or t.__class__.__name__.lower() == "boolean":
                name = c.get("name")
                if name:
                    bool_cols.add(str(name))
    except Exception:
        bool_cols = set()

    _BOOL_COLS_CACHE[table] = bool_cols
    return bool_cols


def _coerce_bools_for_dest(row: dict[str, Any], bool_cols: set[str]) -> dict[str, Any]:
    if not bool_cols:
        return row
    out = dict(row)
    for k in bool_cols:
        if k not in out:
            continue
        v = out[k]
        if v is None or isinstance(v, bool):
            continue
        if isinstance(v, (int, float)):
            out[k] = bool(int(v))
            continue
        if isinstance(v, str):
            s = v.strip().lower()
            if s in {"0", "false", "f", "no", "n"}:
                out[k] = False
            elif s in {"1", "true", "t", "yes", "y"}:
                out[k] = True
    return out


def _insert_rows(db, table: str, rows: Iterable[dict[str, Any]]) -> int:
    """Insert rows via SQLAlchemy session using a text INSERT."""
    from sqlalchemy import text

    rows_list = list(rows)
    if not rows_list:
        return 0

    cols = list(rows_list[0].keys())
    col_sql = ", ".join(cols)
    val_sql = ", ".join([f":{c}" for c in cols])

    # Use plain INSERT; this should run on an empty database.
    stmt = text(f"INSERT INTO {table} ({col_sql}) VALUES ({val_sql})")

    bool_cols = _dest_bool_columns(db, table)

    inserted = 0
    for r in rows_list:
        db.session.execute(stmt, _coerce_bools_for_dest(r, bool_cols))
        inserted += 1
    return inserted


def _set_sequence(db, table: str) -> None:
    """Ensure Postgres sequences are at least max(id)."""
    from sqlalchemy import text

    try:
        # Works only on Postgres; harmless if it errors elsewhere.
        db.session.execute(
            text(
                "SELECT setval(pg_get_serial_sequence(:t, 'id'), COALESCE((SELECT MAX(id) FROM "
                + table
                + "), 1), true)"
            ),
            {"t": table},
        )
    except Exception:
        # Ignore if not Postgres or no sequence.
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate SQLite data to Postgres (Render).")
    parser.add_argument(
        "--sqlite",
        default=str(Path(__file__).resolve().parent / "instance" / "blurkit.db"),
        help="Path to SQLite database file (default: web/instance/blurkit.db)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="TRUNCATE destination tables before importing (DANGEROUS).",
    )
    args = parser.parse_args()

    sqlite_path = Path(args.sqlite).expanduser().resolve()
    if not sqlite_path.exists():
        raise SystemExit(f"SQLite DB not found: {sqlite_path}")

    # Set DATABASE_URL for the Flask app to connect to Postgres
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise SystemExit(
            "Missing DATABASE_URL. Set it to Render *External Database URL* for migration."
        )
    os.environ["DATABASE_URL"] = _normalize_database_url(database_url)

    # Import the Flask app AFTER DATABASE_URL is set.
    from app import app, db  # noqa: WPS433

    # Source
    src = sqlite3.connect(str(sqlite_path))
    tables = _sqlite_tables(src)

    required_tables = ["users", "modalidades", "reglas", "mods", "login_attempts"]
    missing = [t for t in required_tables if t not in tables]
    if missing:
        raise SystemExit(f"SQLite DB is missing tables: {missing}")

    with app.app_context():
        from sqlalchemy import text
        # Create schema on destination
        db.create_all()

        # Safety: refuse to import into a non-empty DB unless --force
        if not args.force:
            for t in required_tables:
                count = db.session.execute(text(f"SELECT COUNT(*) FROM {t}"))
                if int(count.scalar() or 0) != 0:
                    raise SystemExit(
                        f"Destination table '{t}' is not empty. Use --force if you really want to overwrite."
                    )

        if args.force:
            # Reverse dependency order
            for t in ["mods", "reglas", "modalidades", "login_attempts", "users"]:
                db.session.execute(text(f"TRUNCATE TABLE {t} RESTART IDENTITY CASCADE"))
            db.session.commit()

        # Import in dependency order
        imported = {}
        for t in ["users", "modalidades", "reglas", "mods", "login_attempts"]:
            rows = [_coerce_row(r) for r in _sqlite_rows(src, t)]
            imported[t] = _insert_rows(db, t, rows)

        db.session.commit()

        # Fix sequences
        for t in ["users", "modalidades", "reglas", "mods", "login_attempts"]:
            _set_sequence(db, t)
        db.session.commit()

    print("Migration completed.")
    for k, v in imported.items():
        print(f"- {k}: {v} rows")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
