# threatco
companion application for the insights extension. Server / proxy / frontend.

## base install dependencies
- go programming language installed
- a config.json
- start in firstuse mode or there will no way to add a user


## key management
there will be .env support but everything is stored in config.json right now.
secure you server.


## adding the first user (or any!)
```
# create a regular extension user
curl -X POST http://localhost:8081/adduser -d '{"email": "rxlx@nullferatu.com", "admin": false}'

# or with password to get frontend access (the admin flag doesnt corrently do anything)
curl -X POST http://localhost:8081/adduser -d '{"email": "rxlx@nullferatu.com", "admin": true, "password": "beepbo0p"}'
```


### creating a new service

```go
//handlers.go
func (s *Server) ProxyHandler(w http.ResponseWriter, r *http.Request)
  // this function has a switch statement for handling the users incoming request.
  // your service will need to be added to this statement to match the convention.
  // perhaps ill create a list of service names periodically and switch over that instead


//helpers.gp
func (s *Server) YourNewHelper(req ProxyRequest) ([]byte, error)
  // here you should do the request and transform you response and return
```
create a new entry in the config.json for your new service


