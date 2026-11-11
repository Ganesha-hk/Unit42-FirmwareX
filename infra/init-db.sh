#!/bin/sh
set -eu
# bootstrap generates hexadecimal passwords, so SQL quoting cannot be injected.
case "$FWX_DB_PASSWORD" in *[!0-9a-f]*|'') exit 1;; esac
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE fwxapp LOGIN PASSWORD '$FWX_DB_PASSWORD';
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
