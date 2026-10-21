#!/bin/sh
set -e

flags=""

# Determine flags based on APP_ENV and configuration
if [ "$APP_ENV" = "production" ]; then
    flags="-config /config/config.enc -encoded-config -seedfile /readme"
    if [ "$USE_SYSLOG" = "true" ]; then
        flags="$flags -syslog -syslog-host ${SYSLOG_HOST:-localhost:514} -syslog-index ${SYSLOG_INDEX:-threatco}"
    fi
else
    flags="-config /config.json"
    if [ "$USE_SYSLOG" = "true" ]; then
        flags="$flags -syslog -syslog-host ${SYSLOG_HOST:-localhost:514} -syslog-index ${SYSLOG_INDEX:-threatco}"
    fi
fi

# If not using syslog, stream threatco.log to stdout so container logs work
if [ "$USE_SYSLOG" != "true" ]; then
    touch threatco.log
    tail -n 0 -F threatco.log &
fi

# Wait for PostgreSQL to become fully ready and accepting connections
DB_HOST="${DB_HOST:-db}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-threatco}"
DB_NAME="${DB_NAME:-threatco}"

echo "Waiting for PostgreSQL at ${DB_HOST}:${DB_PORT}..."
until pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME"; do
    echo "PostgreSQL is not ready yet - sleeping 1s"
    sleep 1
done
echo "PostgreSQL is ready!"

# Initialize first user if configured and not yet initialized
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@aol.com}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin}"
INIT_ADMIN="${INIT_ADMIN:-true}"

if [ "$INIT_ADMIN" = "true" ] && [ ! -f /tmp/.threatco_initialized ]; then
    echo "Performing first-use setup for admin user (${ADMIN_EMAIL})..."
    /server -firstuse $flags &
    SERVER_PID=$!

    # Wait for server to be responsive
    ATTEMPTS=0
    until curl -s -f http://localhost:8080/ > /dev/null 2>&1 || [ $ATTEMPTS -ge 30 ]; do
        sleep 1
        ATTEMPTS=$((ATTEMPTS + 1))
    done

    # Add the initial admin user
    curl -s -X POST http://localhost:8080/adduser \
        -H "Content-Type: application/json" \
        -d "{\"email\": \"${ADMIN_EMAIL}\", \"password\": \"${ADMIN_PASSWORD}\"}" || true

    # Terminate first-use instance
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    touch /tmp/.threatco_initialized
    echo "First-use admin user setup complete."
fi

# Optional: delete config file if explicitly requested
if [ "$DELETE_CONFIG" = "true" ]; then
    flags="$flags -delete"
fi

echo "Starting ThreatCo server in normal mode..."
exec /server $flags