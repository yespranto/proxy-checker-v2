#!/bin/sh
set -eu

mkdir -p /data/backups
chown -R www-data:www-data /data

# Apply DB migrations (idempotent)
runuser -u www-data -- php /var/www/html/bin/migrate.php

# Background worker, restarted if it crashes
if [ "${WORKER_ENABLED:-1}" = "1" ]; then
  (
    while true; do
      runuser -u www-data -- php /var/www/html/bin/worker.php || true
      sleep 2
    done
  ) &
fi

exec "$@"
