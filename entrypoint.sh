#!/bin/bash

# Prepare log files and start outputting logs to stdout
#touch ./logs/sse.log
#touch ./logs/sse-access.log
#tail -n 0 -f ./logs/sse*.log &

set -e

until PGPASSWORD="$DB_PASSWORD" psql -U "$DB_USER" -h "$DB_HOST" -c '\q' "$DB_NAME"; do
  >&2 echo "Postgres is unavailable - sleeping"
  sleep 5
done

>&2 echo "Postgres is up - starting service"

#export DJANGO_SETTINGS_MODULE=sse.settings
# Apply database migrations
echo "Apply database migrations"
python3 manage.py makemigrations
python3 manage.py migrate --run-syncdb

exec gunicorn SSEServer.wsgi:application \
    --name sse \
    --bind 0.0.0.0:8080 \
    --workers 3
    # --limit-request-line 20000 # This allows long-line requests
    # \
    #--log-level=info \
    #--log-file=./logs/sse.log \
    #--access-logfile=./logs/sse-access.log \
#"$@"
