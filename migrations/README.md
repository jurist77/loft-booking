# SQL migrations

Files are UTF-8/LF: `0001_description.sql`, `0002_description.sql`, …, with no gaps or duplicate versions. Applied files must never be edited, renamed or removed. Add a new migration instead. Do not put credentials or personal data into SQL.

The runner holds a PostgreSQL session advisory lock and applies the pending batch in one transaction. It checks the complete applied prefix (version, filename and SHA-256) before executing new SQL. A failed SQL statement rolls back that pending transaction; there are no automatic down migrations or committed-data deletion.

Do not put BEGIN/COMMIT/ROLLBACK or statements incompatible with a transaction into migration files. Review SQL as trusted deployment code. The migration role owns the `studio` schema; the application role cannot modify migration history. Grant access to future application tables explicitly in their migrations; no automatic broad table grants exist.

Stage 2.1 creates only `studio.schema_migrations` and the schema comment. Bookings, booking events and overlap constraints are deferred to stage 2.2.
