#!/usr/bin/env bash
set -euo pipefail

for role in "$POSTGRES_USER" "$POSTGRES_APP_USER" "$POSTGRES_MIGRATION_USER"; do
  if ! [[ "$role" =~ ^[a-z_][a-z0-9_]{0,62}$ ]]; then
    echo 'Invalid local database role name' >&2; exit 1
  fi
done
if [ "$POSTGRES_USER" = "$POSTGRES_APP_USER" ] || [ "$POSTGRES_USER" = "$POSTGRES_MIGRATION_USER" ] || [ "$POSTGRES_APP_USER" = "$POSTGRES_MIGRATION_USER" ]; then
  echo 'Distinct bootstrap, application and migration roles are required' >&2; exit 1
fi

# Values come from environment, never password arguments or printed SQL.
psql --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\getenv app_user POSTGRES_APP_USER
\getenv app_password POSTGRES_APP_PASSWORD
\getenv migration_user POSTGRES_MIGRATION_USER
\getenv migration_password POSTGRES_MIGRATION_PASSWORD
\getenv database POSTGRES_DB
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L', :'app_user', :'app_password') \gexec
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L', :'migration_user', :'migration_password') \gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'database') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I, %I', :'database', :'app_user', :'migration_user') \gexec
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SELECT format('CREATE SCHEMA studio AUTHORIZATION %I', :'migration_user') \gexec
SELECT format('GRANT USAGE ON SCHEMA studio TO %I', :'app_user') \gexec
SQL
