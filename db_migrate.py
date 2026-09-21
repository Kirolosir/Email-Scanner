"""Apply ordered PostgreSQL migrations with checksum verification."""
from __future__ import annotations

import argparse
import hashlib
import os
import re
from pathlib import Path

from tenant_store import TenantStoreError


MIGRATION_NAME = re.compile(r"^[0-9]{4}_[a-z0-9_]+\.sql$")
MIGRATION_LOCK_NAME = "email_scanner_schema_migrations"


def discover_migrations(directory):
    directory = Path(directory)
    migrations = []
    for path in sorted(directory.glob("*.sql")):
        if not MIGRATION_NAME.fullmatch(path.name):
            raise TenantStoreError("migration filename is invalid")
        sql = path.read_text(encoding="utf-8")
        if not sql.strip():
            raise TenantStoreError("migration is empty")
        migrations.append((path.name, hashlib.sha256(sql.encode()).digest(), sql))
    if not migrations:
        raise TenantStoreError("no database migrations were found")
    return migrations


def apply_migrations(database, directory):
    migrations = discover_migrations(directory)
    applied = []
    with database.transaction():
        with database.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                (MIGRATION_LOCK_NAME,),
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    name text PRIMARY KEY,
                    checksum bytea NOT NULL,
                    applied_at timestamptz NOT NULL DEFAULT now()
                )
                """
            )
            cursor.execute("SELECT name, checksum FROM schema_migrations")
            existing = dict(cursor.fetchall())
            known = {name for name, _checksum, _sql in migrations}
            unknown = sorted(set(existing) - known)
            if unknown:
                raise TenantStoreError("database contains an unknown migration")
            for name, checksum, sql in migrations:
                recorded = existing.get(name)
                if recorded is not None:
                    if bytes(recorded) != checksum:
                        raise TenantStoreError("an applied migration was modified")
                    continue
                cursor.execute(sql, prepare=False)
                cursor.execute(
                    "INSERT INTO schema_migrations (name, checksum) VALUES (%s, %s)",
                    (name, checksum),
                )
                applied.append(name)
    return applied


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Apply database migrations.")
    parser.add_argument(
        "--directory",
        default=str(Path(__file__).with_name("migrations")),
        help="migration directory",
    )
    return parser.parse_args(argv)


def main(argv=None, env=None):
    args = parse_args(argv)
    values = os.environ if env is None else env
    database_url = str(values.get("DATABASE_URL", ""))
    if not database_url.startswith(("postgresql://", "postgres://")):
        raise TenantStoreError("DATABASE_URL must use PostgreSQL")
    try:
        import psycopg  # noqa: PLC0415 - CLI-only dependency
    except ImportError as exc:
        raise TenantStoreError("PostgreSQL client support is unavailable") from exc
    try:
        with psycopg.connect(database_url) as database:
            apply_migrations(database, args.directory)
    except TenantStoreError:
        raise
    except Exception as exc:  # noqa: BLE001 - never expose connection detail
        raise TenantStoreError("database migration failed") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
