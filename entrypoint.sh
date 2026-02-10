#!/bin/sh
flags=""

set -e

if [ $APP_ENV = "production" ]; then
  flags="-config /config/config.enc -encoded-config -seedfile /readme -syslog"
else
    flags="-syslog -syslog-host 192.168.86.120:514"
fi

# Start the server in first user mode
/server -firstuse $flags &

# Wait for the server to start
sleep 3

# Add the initial user
curl -X POST http://localhost:8080/adduser -d '{"email": "admin@aol.com", "password": "admin"}'

# Stop the server
pkill server

# Wait for the server to stop
sleep 2

# Restart the server in normal mode
/server $flags -delete