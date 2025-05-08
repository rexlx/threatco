package main

import (
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	var logger *log.Logger
	flag.Parse()
	//dsn := "user=postgres password=monkeyintheattic host=%v dbname=threatco"
	//*dbLocation = fmt.Sprintf(dsn, GetDBHost())
	fmt.Println(*dbLocation)
	var c Configuration
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)

	if *useSyslog {
		syslogWriter, err := syslog.Dial("udp", *syslogHost, syslog.LOG_INFO, *syslogIndex)
		if err != nil {
			fmt.Println("Error connecting to syslog:", err)
			os.Exit(1)
		}
		logger = log.New(syslogWriter, "", log.LstdFlags)
	} else {
		file, err := os.OpenFile("threatco.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			fmt.Println("Error opening log file:", err)
			os.Exit(1) // Or handle the error more gracefully
		}
		defer file.Close()
		logger = log.New(file, "", log.LstdFlags)
	}
	s := NewServer("1", ":8081", *dbMode, *dbLocation, logger)

	s.InitializeFromConfig(&c, true)
	PassStore(&UploadStore{Files: make(map[string]UploadHandler), Memory: &sync.RWMutex{}, ServerConfig: &c})
	ticker := time.NewTicker(time.Duration(c.StatCacheTickRate) * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				s.UpdateCharts()
				go s.updateCache()
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

	svr := &http.Server{
		Addr:    s.Details.Address,
		Handler: s.Session.LoadAndSave(s.Gateway),
	}
	go s.ProcessTransientResponses()
	s.LogInfo(fmt.Sprintf("Server started at %s", s.Details.Address))
	log.Fatal(svr.ListenAndServe())
}
