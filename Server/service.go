package server

import (
	"context"
	"fmt"
	"kairos-server/adapters"
	"kairos-server/types"
	"os"
	"strconv"
	"sync"

	log "github.com/sirupsen/logrus"
)

type (
	Service struct {
		WSHandler adapters.MultiWSH
		WebServer adapters.Server
		SQL       adapters.SQL
	}
)

func (s *Service) Start(ctx context.Context) {
lifecycle:
	for range ctx.Done() {
		log.Info("context cancelled")
		s.Shutdown(ctx)
		break lifecycle
	}
}

func SetupService(ctx context.Context) *Service {
	wsCfg, err := setupServiceCfg()
	if err != nil {
		log.Fatal(err)
	}

	sqlite, err := adapters.ConnectToSqlite()
	if err != nil {
		log.Fatal(err)
	}
	log.Info("Connected to Sqlite DB")

	go sqlite.StartJobStatusUpdater(ctx, types.Running)
	log.Info("Starting Job Status Updater")

	llmClient, err := adapters.SetupOllamaAPI()
	if err != nil {
		log.Fatal(err)
	}
	log.Info("Setup Ollama API")

	llmTke, err := adapters.SetupTokenCounter("cl100k_base")
	if err != nil {
		log.Fatal(err)
	}
	log.Info("Setup LLM Tokenizer")

	llm := adapters.LLM{
		Client: llmClient,
		Tke:    llmTke,
	}

	runnerMgr := adapters.SetupRunnerManager()

	multiWebsocketHandler := adapters.SetupMultiWSHandler(runnerMgr, sqlite, &llm)
	log.Info("Started Websocket Handler")

	srv := adapters.SetupHTTPServer(*wsCfg, *multiWebsocketHandler)
	log.Info("Start HTTP Server")

	return &Service{
		WSHandler: multiWebsocketHandler,
		WebServer: *srv,
		SQL:       sqlite,
	}
}

func setupServiceCfg() (*adapters.ServerCfg, error) {
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

	var wsCfg = adapters.ServerCfg{
		Address: wsAddr,
		Port:    wsPort,
	}

	return &wsCfg, nil
}

func (s *Service) Shutdown(ctx context.Context) {
	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		s.SQL.Close()
		log.Info("disconnected from sqlite")
	}(wg)

	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		log.Info("shutting down http server handler")
		if err := s.WebServer.Shutdown(ctx); err != nil {
			log.Errorf("unable to shutdown http server: %v", err)
		}
	}(wg)

	wg.Wait()
}
