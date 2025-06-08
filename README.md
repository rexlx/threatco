# threatco
companion application for the insights extension. Server / proxy / frontend.

## base install dependencies
- go programming language installed
- a config.json
- start in firstuse mode or there will no way to add a user

## containerized deployment
- docker, podman, or docker-compose
- Dockerfile(s) / entrypoint.sh located in the root directory of this folder
- a configuration file is also needed. the -delete option remove the config after reading it in.
- environment variables if secrets need to be hidden
- creates a user admin@aol.com with password admin for the frontend

## adding the first user (or any!)
```
# create a regular extension user (no password is required, so none is set)
curl -X POST http://localhost:8081/adduser -d '{"email": "rxlx@nullferatu.com", "admin": false}'

# or with password to get frontend access (the admin flag doesnt corrently do anything)
curl -X POST http://localhost:8081/adduser -d '{"email": "rxlx@nullferatu.com", "admin": true, "password": "beepbo0p"}'
```

## supported plugins
- [misp](https://github.com/MISP/MISP)
- crowdstrike
- mandiant
- vmray (limited to file upload)
- virustotal
- domaintools
- [deepfry](https://github.com/rexlx/deepfry)




