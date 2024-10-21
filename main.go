package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	flag.Parse()
	s := NewServer("1", ":8080", *dbLocation)

	bear := KeyAuth{Token: *mispKey}
	vtAuth := XAPIKeyAuth{Token: *vtKey}
	ticker := time.NewTicker(150 * time.Second)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	misp := NewEndpoint(*mispUrl, &bear, true, s.RespCh)
	vt := NewEndpoint("https://www.virustotal.com/api/v3", &vtAuth, false, s.RespCh)
	vt.RateLimited = true
	vt.MaxRequests = 4
	vt.RefillRate = 61 * time.Second
	s.Targets["virustotal"] = vt
	s.Targets["misp"] = misp
	go func() {
		for {
			select {
			case <-ticker.C:
				s.updateCache()
			case <-sigs:
				s.Log.Println("Shutting down")
				ticker.Stop()
				os.Exit(0)
			}
		}
	}()

	svr := &http.Server{
		Addr:    s.Details.Address,
		Handler: s.Gateway,
	}
	go s.ProcessTransientResponses()
	s.Log.Printf("Server started at %s", s.Details.Address)
	log.Fatal(svr.ListenAndServe())
}
