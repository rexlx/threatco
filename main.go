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
	ticker := time.NewTicker(150 * time.Second)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	misp := NewEndpoint(*mispUrl, &bear, true)
	s.Targets["misp"] = misp

	go func() {
		for {
			select {
			case <-ticker.C:
				s.Memory.RLock()
				s.Log.Printf("Stats: %v\n", s.Details.Stats)
				s.Memory.RUnlock()
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
	s.Log.Printf("Server started at %s", s.Details.Address)
	log.Fatal(svr.ListenAndServe())
}
