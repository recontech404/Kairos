//go:build !darwin

package runner

import (
	"context"
	"fmt"
	"kairos-runner/adapters"
	"kairos-runner/extractors"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	log "github.com/sirupsen/logrus"
)

type (
	Service struct {
		WSH            *adapters.WSHandler
		Shutdown       chan struct{}
		ShutdownNoTerm chan struct{}
		JobDone        chan struct{} //to tell ebpf event receivers to send all data
		DoneSending    chan struct{} //to tell when all data is done being sent - time.sleep does not work for large data/slow network
		CancelCtx      context.CancelFunc

		WSConnDetails *adapters.WSConnDetails //for ws reconnection

		VerboseLog bool
	}
)

func (s *Service) Start(ctx context.Context) {
	go extractors.StarteBPFCaptures(ctx, s.WSH, s.VerboseLog, s.JobDone, s.DoneSending)
	go extractors.StartJobListener(ctx, s.WSH, s.JobDone, s.Shutdown, s.ShutdownNoTerm)

	for {
		select {
		case <-s.Shutdown:
			s.Stop(ctx)
			return
		case <-s.ShutdownNoTerm:
			s.StopWithoutTerm(ctx)
			return
		case <-ctx.Done():
			return
		}
	}
}

func (s *Service) Stop(ctx context.Context) {
	for {
		select {
		case <-s.DoneSending:
			log.Info("Done Uploading Data")
			log.Info("Runner lifecycle complete ---> shutting down completely")
			s.cleanUp()
			log.Info("All Services Disconnected ------> Shutdown Now")
			return
		}
	}
}

func (s *Service) StopWithoutTerm(ctx context.Context) {
	for {
		select {
		case <-s.DoneSending:
			log.Info("Done Uploading Data")
			log.Info("Runner lifecycle complete ---> keep alive selected")
			s.cleanUp()
			log.Info("All Services Disconnected ------> Keeping Alive")

			sleepSig := s.setupSleepSignal()

			for {
				select {
				case <-sleepSig:
					return
				}
			}
		}
	}

}

func (s *Service) cleanUp() {
	s.CancelCtx()
	log.Info("Disconnecting from websocket connection")
	s.WSH.Disconnect()
	close(s.Shutdown)
	close(s.ShutdownNoTerm)
	close(s.DoneSending)
	close(s.JobDone)
}

func (s *Service) setupSleepSignal() chan bool {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan bool)

	go func() {
		sig := <-signalChan
		log.Printf("Sleep Shutdown Received: %v\n", sig)
		done <- true
	}()

	return done
}

func SetupService(ctx context.Context, cancelCtx context.CancelFunc) *Service {
	shutdown := make(chan struct{})
	shutdownNoTerm := make(chan struct{})
	jobDone := make(chan struct{})
	doneSending := make(chan struct{})

	wsCfg, err := setupWSConfig()
	if err != nil {
		log.Fatal(err)
	}

	logLevel, err := setupLogLevel()
	if err != nil {
		log.Fatal(err)
	}

	ws := adapters.SetupWebsocket(ctx, *wsCfg)

	return &Service{
		WSH:            ws,
		Shutdown:       shutdown,
		ShutdownNoTerm: shutdownNoTerm,
		JobDone:        jobDone,
		DoneSending:    doneSending,
		CancelCtx:      cancelCtx,
		WSConnDetails:  wsCfg,
		VerboseLog:     logLevel,
	}
}

func setupWSConfig() (*adapters.WSConnDetails, error) {
	wsAddr := os.Getenv("WS_ADDRESS")
	if wsAddr == "" {
		return nil, fmt.Errorf("ws addr cannot be empty")
	}

	wsRawPort := os.Getenv("WS_PORT")
	if wsRawPort == "" {
		return nil, fmt.Errorf("ws port cannot be empty")
	}

	wsPort, err := strconv.Atoi(wsRawPort)
	if err != nil {
		return nil, fmt.Errorf("ws port is not valid")
	}

	wsRawTLS := os.Getenv("SKIP_VERIFY_TLS")
	if wsRawTLS == "" {
		return nil, fmt.Errorf("skip verify tls cannot be empty")
	}

	skipVerifyTLS, err := strconv.ParseBool(wsRawTLS)
	if err != nil {
		return nil, fmt.Errorf("skip verify tls not a valid bool")
	}

	var wsCfg = adapters.WSConnDetails{
		Address:       wsAddr,
		Port:          wsPort,
		SkipTLSVerify: skipVerifyTLS,
	}

	return &wsCfg, nil
}

func setupLogLevel() (bool, error) {
	rawLVL := os.Getenv("LOG_V")
	if rawLVL == "" {
		return false, nil
	}

	verboseLog, err := strconv.ParseBool(rawLVL)
	if err != nil {
		return false, fmt.Errorf("unable to parse verbose log: %v", err)
	}

	return verboseLog, nil
}
