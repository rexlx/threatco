# API Guide for Threatco Server

## Authentication
all requests are authenticated and require an auth header with crendentials provided by your admin.

```
"Authorization: beep@boop.com:bOtHGzBR+XXGEozPnoyXzo7192eJ1NeN3QtdgNaMXPE="
```

## Significant Routes


### examples

```bash
# GET LOGS. get list of logs ordered by when they occurred
curl http://localhost:8081/logs -H "Authorization: admin@admin.com:UmLPBz7zDXx1UreAJa+TupuBabP8T9wxr0yLTWiCnfQ="

# response is a list of logs
# [{"time":"2025-01-30T07:15:11.800719266-06:00","data":"Server started at :8081","error":false}]

# GET RESPONSE. use the event id of a response (referred to as 'link' by field name)
curl http://localhost:8081/events/caf24585-b21a-4616-9958-30b9d90fd45a -H "Authorization: admin@admin.com:UmLPBz7zDXx1UreAJa+TupuBabP8T9wxr0yLTWiCnfQ="

# response is the literal response from the vendor byte for byte and is impossible to represent here.

# PROXY REQUEST. perform a proxy request to the demo vendor 'deepfry'
# ACCEPTS:
# value  : the value to be queried
# to     : which vendor to proxy to: "misp" "mandiant" "virustotal" (vmray is fileupload only at the moment)
# type   : type of indicator -> "md5", "sha1", "sha256", "sha512", "ipv4", "ipv6", "email", "url", "domain", "filepath", "filename"
# route  : associated route if not the base URL
curl -X POST http://localhost:8081/pipe -H "Authorization: admin@admin.com:UmLPBz7zDXx1UreAJa+TupuBabP8T9wxr0yLTWiCnfQ=" -d '{"value": "8.8.8.8", "to": "deepfry", "type": "ipv4", "username": "any@string.here"}'

# response:
# {"timestamp":"0001-01-01T00:00:00Z","matched":true,"error":false,"background":"has-background-primary-dark","from":"deepfry","id":"1","attr_count":0,"link":"4f82d899-9572-4aa0-a584-04fe0f30168b","threat_level_id":"1","value":"8.8.8.8","info":"that IP looks nosey!"}

curl -X POST http://localhost:8081/parse -H "Authorization: test@aol.com:UmLPBz7zDXx1UreAJa+TupuBabP8T9wxr0yLTWiCnfQ=" -d '{"username": "test@aol.com", "blob": "159.203.188.91"}'

# the response is a list of summarized responses exactly like the one above.
```

### file upload

```bash
#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <file_path>"
    exit 1
fi

# Assign the first argument to the file_path variable
file_path=$1

# Define the URL and headers
url="http://localhost:8081/upload"
authorization="admin@admin.com:UmLPBz7zDXx1UreAJa+TupuBabP8T9wxr0yLTWiCnfQ="
filename=$(basename "$file_path")

# Upload the file
curl -X POST "$url" \
    -H "Authorization: $authorization" \
    -H "Content-Type: application/octet-stream" \
    -H "X-filename: $filename" \
    -H "X-last-chunk: true" \
    --data-binary @"$file_path"

# response informs user of the status of the upload to the PROXY server, not vmray. view events/id to see me information
# {"status":"complete","id":"af7bd5af-e4fc-4a6c-8cdb-cc341870ec3e"}
```