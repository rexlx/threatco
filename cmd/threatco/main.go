package main

import (
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rexlx/threatco/internal"
)

func main() {
	var logger *log.Logger
	flag.Parse()
	var c internal.Configuration
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)

	if *internal.UseSyslog {
		syslogWriter, err := syslog.Dial("udp", *internal.SyslogHost, syslog.LOG_INFO, *internal.SyslogIndex)
		if err != nil {
			fmt.Println("Error connecting to syslog:", err)
			os.Exit(1)
		}
		logger = log.New(syslogWriter, "", log.LstdFlags)
	} else {
		file, err := os.OpenFile("threatco.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			fmt.Println("Error opening log file:", err)
			os.Exit(1)
		}
		defer file.Close()
		logger = log.New(file, "", log.LstdFlags)
		// logger = log.New(os.Stdout, "", log.LstdFlags| log.Lshortfile)
	}
	s := internal.NewServer("", ":8080", *internal.DbMode, *internal.DbLocation, logger)

	s.InitializeFromConfig(&c, true)
	internal.PassStore(internal.NewUploadStore(&c))
	ticker := time.NewTicker(time.Duration(c.StatCacheTickRate) * time.Second)
	healthTicker := time.NewTicker(time.Duration(*internal.HealthCheck) * time.Second)
	go func() {
		go s.SimpleServiceCheck()
		for {
			select {
			case <-ticker.C:
				s.UpdateCharts()
				go s.UpdateCache()
			case <-healthTicker.C:
				// fmt.Println("Performing health check")
				go s.SimpleServiceCheck()
			case <-sigs:
				s.Log.Println("Shutting down")
				ticker.Stop()
				os.Exit(0)
			case <-s.StopCh:
				s.Log.Println("Shutting down")
				ticker.Stop()
				os.Exit(0)
			}
		}
	}()

	sessionHandler := s.Session.LoadAndSave(s.Gateway)
	finalHandler := internal.CORSMiddleware(sessionHandler)
	svr := &http.Server{
		Addr:    s.Details.Address,
		Handler: finalHandler,
	}
	go s.ProcessTransientResponses()
	s.LogInfo(fmt.Sprintf("Server started at %s", s.Details.Address))
	log.Fatal(svr.ListenAndServe())
}
