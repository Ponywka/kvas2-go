package main

import (
	"context"
	"github.com/rs/zerolog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	app, err := New(Config{
		MinimalTTL:             time.Hour,
		ChainPostfix:           "KVAS2_",
		IpSetPostfix:           "kvas2_",
		TargetDNSServerAddress: "127.0.0.1:53",
		ListenPort:             7548,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize application")
	}

	ctx, cancel := context.WithCancel(context.Background())

	appResult := make(chan error)
	go func() {
		appResult <- app.Listen(ctx)
	}()

	log.Info().Msg("starting service")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case err, _ := <-appResult:
			if err != nil {
				log.Error().Err(err).Msg("failed to start application")
			}
			log.Info().Msg("exiting application")
			return
		case <-c:
			log.Info().Msg("shutting down service")
			cancel()
		}
	}
}
