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

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rexlx/threatco/internal"
)

func main() {
	var logger *log.Logger
	flag.Parse()
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
	}
	s, c := internal.NewServer("", ":8080", *internal.DbMode, *internal.DbLocation, logger)
	internal.PassStore(internal.NewUploadStore(c))

	ticker := time.NewTicker(time.Duration(c.StatCacheTickRate) * time.Second)
	healthTicker := time.NewTicker(time.Duration(*internal.HealthCheck) * time.Second)

	feedTicker := time.NewTicker(4 * time.Hour)

	go func() {
		go s.SimpleServiceCheck()
		go s.PollVulnerabilityFeeds()

		for {
			select {
			case <-ticker.C:
				s.UpdateCharts()
				go s.UpdateCache()
			case <-healthTicker.C:
				go s.SimpleServiceCheck()
				go s.AutomatedThreatScan()
			case <-feedTicker.C:
				go s.PollVulnerabilityFeeds()
			case <-sigs:
				s.Log.Println("Shutting down")
				ticker.Stop()
				feedTicker.Stop()
				os.Exit(0)
			case <-s.StopCh:
				s.Log.Println("Shutting down")
				ticker.Stop()
				feedTicker.Stop()
				os.Exit(0)
			}
		}
	}()

	promMux := http.NewServeMux()
	promMux.Handle("/metrics", promhttp.Handler())

	promSrv := &http.Server{
		Addr:    ":8089",
		Handler: promMux,
	}

	go func() {
		fmt.Println("Starting Prometheus monitoring on :8089/metrics")
		if err := promSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Prometheus listener error: %v\n", err)
		}
	}()

	sessionHandler := s.Session.LoadAndSave(s.Gateway)
	finalHandler := s.CORSMiddleware(sessionHandler)
	svr := &http.Server{
		Addr:    s.Details.Address,
		Handler: finalHandler,
	}
	go s.ProcessTransientResponses()
	s.Details.StartTime = time.Now()
	s.LogInfo(fmt.Sprintf("(%v)\tServer started at %s with ID %s", s.Details.Address, s.Details.StartTime, s.ID))
	log.Fatal(svr.ListenAndServe())
}
