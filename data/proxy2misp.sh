#!/bin/bash

if [ "$#" -ne 1 ]; then
	echo "Usage: $0 <value>"
	exit 1
fi
value=$1
curl -k -X POST http://localhost:8081/pipe \
		-H "Authorization: beep@boop.com:bOtHGzBR+XXGEozPnoyXzo7192eJ1NeN3QtdgNaMXPE=" \
		-H "Content-Type: application/json" \
		-d "{\"value\": \"$value\", \"to\": \"misp\", \"type\": \"ipv4\"}"

