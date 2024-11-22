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
	var c Configuration
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	s := NewServer("1", ":8081", *dbLocation)

	s.InitializeFromConfig(&c, true)
	ticker := time.NewTicker(time.Duration(c.StatCacheTickRate) * time.Second)
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
		Handler: s.Session.LoadAndSave(s.Gateway),
	}
	go s.ProcessTransientResponses()
	s.Log.Printf("Server started at %s", s.Details.Address)
	log.Fatal(svr.ListenAndServe())
}
