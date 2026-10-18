# SQLite migrations

Active SQL lives in `migrations/sqlite/`. PostgreSQL's original migration is retained unchanged at `docs/archive/postgresql/0001_foundation.sql` for provenance; it is NEVER applied to SQLite. This is a new SQLite history, not an in-place conversion of PostgreSQL SQL/data.

Use UTF-8/LF and contiguous `0001_description.sql`, `0002_description.sql`, … filenames. Applied files cannot be edited, renamed or removed. `schema_migrations` stores version, filename, SHA-256 and timestamp. The runner uses `BEGIN IMMEDIATE` and one transaction for pending SQL + history. SQLite serializes independent writers; a timed-out competing migrator fails with `MIGRATION_LOCKED`. Re-running applies zero new versions. History mismatch or SQL failure returns nonzero; pending DDL/history rolls back atomically. No down migrations/data deletion occur.

Do not include BEGIN/COMMIT/ROLLBACK or nontransactional operations in migration files. SQL is reviewed trusted code, not user input. Backup before schema changes; app rollback cannot undo an incompatible schema migration.

The initial SQLite foundation includes a small health write-probe row and a minimal bookings interval table with INSERT/UPDATE overlap triggers. There are no contacts, booking REST endpoints, admin UI or notification operations. Application API/idempotency/privacy work is separately scoped. Adjacent `[start,end)` intervals are allowed; cancelled rows release time without deletion.
