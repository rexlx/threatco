# threatco
companion application for the [insights](https://github.com/rexlx/insights) [extension](https://chromewebstore.google.com/detail/insights/ahjeboeknahakdlhjilhhjlddijbcooi). proxy requests to third party APIs for IOC enrichment.

### key features
- enrich users query by fanning out to all available plugins (third-party APIs)
- file analysis
- parse blobs of text sent over API to extract IOC and enrich
- frontend with user management, knowledge base, runtime stats, response list
- view statistics and application performance
- remote logging if desired

## base install dependencies
- go programming language installed
- git
- *optionally* docker
- a config.json / .env if secret management is required

## containerized deployment
- docker, podman, or docker-compose
- Dockerfile(s) / entrypoint.sh located in the root directory of this folder
- a configuration file is required and is copied in at image creation. if you dont want secrets in your container consider using environment variables (see env section below)
- .env / environment variables if secrets need to be hidden
- entrypoint.sh creates a user admin@aol.com with password admin for the frontend

## env
you can enhance the security of your deployment by omitting **keys and secrets** from your config. after the app loads the configuration, it will check if any service keys are empty, if any are found it will search in the environment for SERVICE_KEY and SERVICE_SECRET (using the Service.Kind field as the SERVICE name).

in the example below the app would look for MISP_KEY and MISP_SECRET (even though misp only uses the key value by convention).

```bash
VIRUSTOTAL_KEY="foobarxyz"
VIRUSTOTAL_SECRET="only include a secret if you have one (sometimes a secret is a username)"
URLSCAN_KEY="thisisntmykey"
URLSCAN_SECRET="" # you can leave the value blank if youre unsure, but it can also be omitted .
MISP_KEY="yougettheidea"
THREATCO_DB_LOCATION="user=neo password=morpheus host=127.0.0.1 dbname=threatco"
```

```json
{       
"name": "special-misp-dont-use-this-name",
"url": "https://192.168.122.68:443",
"rate_limited": false,
"insecure": true,
"auth_type": "token",
"key": "",
"kind": "misp",
"type": ["md5", "sha1", "sha256", "sha512", "ipv4", "ipv6", "email", "url", "domain", "filepath", "filename"],
"description": "leave the key empty in the config entry but DO add it to your ENV!"
},
 ```

## adding the first user (or any!)
```bash
# create a regular extension user (no password is required, so none is set)
curl -X POST http://localhost:8080/adduser -d '{"email": "rxlx@nullferatu.com", "admin": false}'

# or with password to get frontend access (the admin flag doesnt currently do anything)
curl -X POST http://localhost:8081/adduser -d '{"email": "rxlx@nullferatu.com", "admin": true, "password": "beepbo0p"}'
```

## supported plugins
- crowdstrike
- [deepfry](https://github.com/rexlx/deepfry)
- domaintools
- [livery](https://github.com/rexlx/livery)
- mandiant
- [misp](https://github.com/MISP/MISP)
- splunk (*limited access*)
- urlscan
- virustotal
- vmray (*limited to file upload*)




