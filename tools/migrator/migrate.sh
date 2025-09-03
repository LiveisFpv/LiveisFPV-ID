#!/bin/sh
echo "Running migrations..."
cd ./tools/migrator || exit 1
go run main.go --user="$DB_USER" --password="$DB_PASSWORD" --host="$DB_HOST" --port="$DB_PORT" --dbname="$DB_NAME" --migrations-path=../../db/migrations