//go:build !darwin

package main

import (
	"context"
	runner "kairos-runner"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
)

func cancelContextOnTermination() (context.Context, context.CancelFunc) {
	cancelChan := make(chan os.Signal, 1)
	signal.Notify(cancelChan, syscall.SIGTERM, syscall.SIGINT)
	cancelContext, cancel := context.WithCancel(context.Background())

	go func() {
		sig := <-cancelChan
		log.Infof("signal caught: %v", sig)
		cancel()
	}()

	return cancelContext, cancel
}

func main() {
	ctx, cancel := cancelContextOnTermination()

	log.Info("Setting up adapters")
	service := runner.SetupService(ctx, cancel)

	log.Info("Starting runner service")
	service.Start(ctx)
}
