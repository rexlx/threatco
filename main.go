package main

import (
	"flag"
	"log"
	"net/http"
)

func main() {
	flag.Parse()
	s := NewServer("1", "localhost:8080")

	bear := KeyAuth{Token: *mispKey}
	misp := NewEndpoint(*mispUrl, &bear, true)
	s.Targets["misp"] = misp

	svr := &http.Server{
		Addr:    s.Details.Address,
		Handler: s.Gateway,
	}
	s.Log.Printf("Server started at %s", s.Details.Address)
	log.Fatal(svr.ListenAndServe())
}
