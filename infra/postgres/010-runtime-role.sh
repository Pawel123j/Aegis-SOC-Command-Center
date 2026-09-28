#!/bin/sh
set -eu

# psql quotes values as SQL literals/identifiers; the password is never SQL source.
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    --set=ON_ERROR_STOP=1 \
    --set=app_password="$POSTGRES_APP_PASSWORD" \
    --set=database_name="$POSTGRES_DB" <<'SQL'
CREATE ROLE aegis_app LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
    PASSWORD :'app_password';
REVOKE ALL ON DATABASE :"database_name" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"database_name" TO aegis_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO aegis_app;
SQL
