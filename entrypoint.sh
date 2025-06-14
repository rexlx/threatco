#!/bin/sh

# Start the server in first user mode
/server -firstuse &

# Wait for the server to start
sleep 3

# Add the initial user
curl -X POST http://localhost:8081/adduser -d '{"email": "admin@aol.com", "password": "admin"}'

# Stop the server
killall server

# Wait for the server to stop
sleep 2

# Restart the server in normal mode
/server -delete