package main

import (
	"context"
	server "kairos-server"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
)

func cancelContextOnTermination() context.Context {
	cancelChan := make(chan os.Signal, 1)
	signal.Notify(cancelChan, syscall.SIGTERM, syscall.SIGINT)
	cancelContext, cancel := context.WithCancel(context.Background())

	go func() {
		sig := <-cancelChan
		log.Infof("signal caught: %v", sig)
		cancel()
	}()

	return cancelContext
}

func main() {
	ctx := cancelContextOnTermination()

	log.Info("Setting up adapters")
	service := server.SetupService(ctx)

	log.Info("Starting Server Service")
	service.Start(ctx)
}
